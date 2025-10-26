import { AwsClient } from 'aws4fetch'

const HOMEPAGE = 'https://github.com/milkey-mouse/git-lfs-s3-proxy'
const EXPIRY = 3600

const MIME = 'application/vnd.git-lfs+json'

const METHOD_FOR = {
  upload: 'PUT',
  download: 'GET',
}

// Whitelisted buckets - only these buckets can be used with this proxy
const ALLOWED_BUCKETS = [
  's3.eu-central-003.backblazeb2.com/dorfarchiv-roessing',
]

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

async function fetch(req, env) {
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
      // Get credentials from query parameters
      const keyId = url.searchParams.get('keyId')
      const appKey = url.searchParams.get('appKey')

      if (!keyId || !appKey) {
        return new Response(JSON.stringify({ message: 'Missing keyId or appKey query parameters' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        })
      }

      // Step 1: Authorize account with B2
      const credentials = `${keyId}:${appKey}`
      const encodedCredentials = btoa(credentials)

      const authResponse = await fetch('https://api.backblazeb2.com/b2api/v2/b2_authorize_account', {
        headers: {
          'Authorization': `Basic ${encodedCredentials}`
        }
      })

      if (!authResponse.ok) {
        throw new Error(`B2 authorization failed: ${authResponse.status}`)
      }

      const authData = await authResponse.json()
      const { authorizationToken, downloadUrl, allowed, apiUrl } = authData
      const bucketId = allowed.bucketId

      // Step 2: Get download authorization with content-disposition
      const downloadAuthResponse = await fetch(`${apiUrl}/b2api/v2/b2_get_download_authorization`, {
        method: 'POST',
        headers: {
          'Authorization': authorizationToken,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          bucketId: bucketId,
          fileNamePrefix: oid,
          validDurationInSeconds: EXPIRY,
          b2ContentDisposition: `attachment; filename="${filename}"`
        })
      })

      if (!downloadAuthResponse.ok) {
        throw new Error(`Download authorization failed: ${downloadAuthResponse.status}`)
      }

      const downloadAuthData = await downloadAuthResponse.json()
      const downloadAuthToken = downloadAuthData.authorizationToken

      // Step 3: Redirect to B2 download URL with authorization token and content-disposition
      const contentDisposition = encodeURIComponent(`attachment; filename="${filename}"`)
      const fileUrl = `${downloadUrl}/file/dorfarchiv-roessing/${oid}?Authorization=${downloadAuthToken}&b2ContentDisposition=${contentDisposition}`

      return Response.redirect(fileUrl, 302)
    } catch (err) {
      return new Response(JSON.stringify({
        message: 'Error generating download URL',
        error: err.message,
        stack: err.stack
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      })
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

  const { user, pass } = parseAuthorization(req)
  let s3Options = { accessKeyId: user, secretAccessKey: pass }

  const segments = url.pathname.split('/').slice(1, -2)
  let params = {}
  let bucketIdx = 0
  for (const segment of segments) {
    const sliceIdx = segment.indexOf('=')
    if (sliceIdx === -1) {
      break
    } else {
      const key = decodeURIComponent(segment.slice(0, sliceIdx))
      const val = decodeURIComponent(segment.slice(sliceIdx + 1))
      s3Options[key] = val

      bucketIdx++
    }
  }

  const s3 = new AwsClient(s3Options)
  const bucket = segments.slice(bucketIdx).join('/')

  // Check if bucket is whitelisted
  if (!ALLOWED_BUCKETS.includes(bucket)) {
    return new Response(
      JSON.stringify({
        message: `Access to bucket '${bucket}' is not allowed. Only whitelisted buckets can be used with this proxy.`,
      }),
      {
        status: 403,
        headers: { 'Content-Type': MIME },
      },
    )
  }

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

export default { fetch }
