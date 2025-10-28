import { AwsClient } from 'aws4fetch'

const HOMEPAGE = 'https://github.com/milkey-mouse/git-lfs-s3-proxy'
const EXPIRY = 3600

const MIME = 'application/vnd.git-lfs+json'

const METHOD_FOR = {
  upload: 'PUT',
  download: 'GET',
}

// Environment variables required for this worker:
// - B2_BUCKET_NAME: The name of the Backblaze B2 bucket (e.g., "dorfarchiv-roessing")
// - B2_BUCKET_HOST: The Backblaze B2 bucket host (e.g., "s3.eu-central-003.backblazeb2.com")
// - B2_KEY_ID: The Backblaze B2 application key ID for read access
// - B2_APP_KEY: The Backblaze B2 application key for read access

async function sign(s3, bucket, path, method) {
  const info = { method }
  const signed = await s3.sign(
    new Request(`https://${bucket}/${path}?X-Amz-Expires=${EXPIRY}`, info),
    { aws: { signQuery: true } },
  )
  return signed.url
}

function parseAuthorization(req) {
  const auth = req.headers.get('Authorization')
  if (!auth) {
    throw new Response(null, { status: 401 })
  }

  const [scheme, encoded] = auth.split(' ')
  if (scheme !== 'Basic' || !encoded) {
    throw new Response(null, { status: 400 })
  }

  const buffer = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0))
  const decoded = new TextDecoder().decode(buffer).normalize()
  const index = decoded.indexOf(':')
  if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
    throw new Response(null, { status: 400 })
  }

  return { user: decoded.slice(0, index), pass: decoded.slice(index + 1) }
}

async function handleRequest(req, env) {
  const url = new URL(req.url)

  if (url.pathname == '/') {
    if (req.method === 'GET') {
      return Response.redirect(HOMEPAGE, 302)
    } else {
      return new Response(null, { status: 405, headers: { Allow: 'GET' } })
    }
  }

  // Handle download endpoint: /download/{oid}/{filename}
  const downloadMatch = url.pathname.match(/^\/download\/([a-f0-9]{64})\/(.+)$/)
  if (downloadMatch) {
    if (req.method !== 'GET') {
      return new Response(null, { status: 405, headers: { Allow: 'GET' } })
    }

    const [, oid, filename] = downloadMatch

    try {
      // Get credentials from environment variables
      const keyId = env.B2_KEY_ID
      const appKey = env.B2_APP_KEY
      const bucketName = env.B2_BUCKET_NAME

      if (!keyId || !appKey || !bucketName) {
        return new Response(
          JSON.stringify({
            message: 'Missing required environment variables: B2_KEY_ID, B2_APP_KEY, and B2_BUCKET_NAME must be configured',
          }),
          {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
          },
        )
      }

      // Step 1: Authorize account with B2
      const credentials = `${keyId}:${appKey}`
      const encodedCredentials = btoa(credentials)

      const authResponse = await fetch(
        'https://api.backblazeb2.com/b2api/v2/b2_authorize_account',
        {
          headers: {
            Authorization: `Basic ${encodedCredentials}`,
          },
        },
      )

      if (!authResponse.ok) {
        throw new Error(`B2 authorization failed: ${authResponse.status}`)
      }

      const authData = await authResponse.json()
      const { authorizationToken, downloadUrl, allowed, apiUrl } = authData
      const bucketId = allowed.bucketId

      // Step 2: Determine content type based on file extension
      const lowerFilename = filename.toLowerCase()
      const contentType = lowerFilename.endsWith('.mp4') ? 'video/mp4' :
                          lowerFilename.endsWith('.zip') ? 'application/zip' :
                          lowerFilename.endsWith('.pdf') ? 'application/pdf' :
                          lowerFilename.endsWith('.dwg') ? 'application/acad' :
                          'application/octet-stream'

      // Step 3: Get download authorization with content-disposition and content-type
      const downloadAuthResponse = await fetch(
        `${apiUrl}/b2api/v2/b2_get_download_authorization`,
        {
          method: 'POST',
          headers: {
            Authorization: authorizationToken,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            bucketId: bucketId,
            fileNamePrefix: oid,
            validDurationInSeconds: EXPIRY,
            b2ContentDisposition: `inline; filename="${filename}"`,
            b2ContentType: contentType,
          }),
        },
      )

      if (!downloadAuthResponse.ok) {
        throw new Error(
          `Download authorization failed: ${downloadAuthResponse.status}`,
        )
      }

      const downloadAuthData = await downloadAuthResponse.json()
      const downloadAuthToken = downloadAuthData.authorizationToken

      // Step 4: Redirect to B2 download URL with authorization token, content-disposition and content-type
      const contentDisposition = encodeURIComponent(
        `inline; filename="${filename}"`,
      )
      const encodedContentType = encodeURIComponent(contentType)
      const fileUrl = `${downloadUrl}/file/${bucketName}/${oid}?Authorization=${downloadAuthToken}&b2ContentDisposition=${contentDisposition}&b2ContentType=${encodedContentType}`

      return Response.redirect(fileUrl, 302)
    } catch (err) {
      return new Response(
        JSON.stringify({
          message: 'Error generating download URL',
          error: err.message,
          stack: err.stack,
        }),
        {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        },
      )
    }
  }

  if (!url.pathname.endsWith('/objects/batch')) {
    return new Response(null, { status: 404 })
  }

  if (req.method !== 'POST') {
    return new Response(null, { status: 405, headers: { Allow: 'POST' } })
  }

  // in practice, we'd rather not break out-of-spec clients not setting these
  /*if (!req.headers.get("Accept").startsWith(MIME)
    || !req.headers.get("Content-Type").startsWith(MIME)) {
    return new Response(null, { status: 406 });
  }*/

  // Get bucket configuration from environment variables
  const bucketHost = env.B2_BUCKET_HOST
  const bucketName = env.B2_BUCKET_NAME

  if (!bucketHost || !bucketName) {
    return new Response(
      JSON.stringify({
        message: 'Missing required environment variables: B2_BUCKET_HOST and B2_BUCKET_NAME must be configured',
      }),
      {
        status: 500,
        headers: { 'Content-Type': MIME },
      },
    )
  }

  const { user, pass } = parseAuthorization(req)
  let s3Options = { accessKeyId: user, secretAccessKey: pass }

  const segments = url.pathname.split('/').slice(1, -2)
  let params = {}
  for (const segment of segments) {
    const sliceIdx = segment.indexOf('=')
    if (sliceIdx === -1) {
      break
    } else {
      const key = decodeURIComponent(segment.slice(0, sliceIdx))
      const val = decodeURIComponent(segment.slice(sliceIdx + 1))
      s3Options[key] = val
    }
  }

  const s3 = new AwsClient(s3Options)
  const bucket = `${bucketHost}/${bucketName}`

  const expires_in = params.expiry || env.EXPIRY || EXPIRY

  const { objects, operation } = await req.json()
  const method = METHOD_FOR[operation]
  const response = JSON.stringify({
    transfer: 'basic',
    objects: await Promise.all(
      objects.map(async ({ oid, size }) => ({
        oid,
        size,
        authenticated: true,
        actions: {
          [operation]: {
            href: await sign(s3, bucket, oid, method),
            expires_in,
          },
        },
      })),
    ),
  })

  return new Response(response, {
    status: 200,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/vnd.git-lfs+json',
    },
  })
}

export default {
  fetch: handleRequest,
}
