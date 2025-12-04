Wasabi Direct Uploader
======================

A single-file PHP tool for remote uploading files to Wasabi Object Storage
using presigned PUT URLs (no SDK required). Provides a minimal drag & drop
UI for batch upload, progress tracking, and generating share-ready output
in multiple formats (URLs, HTML, Markdown, BBCode, or custom templates).

----------------------------------------------------------------------
FEATURES
----------------------------------------------------------------------

- One PHP file, no dependencies (SDK not required).
- Drag & drop multiple files or select via file picker.
- Generates presigned PUT URLs (AWS SigV4).
- Automatically switches to path-style addressing when bucket name
  contains dots (avoids SSL/host mismatch).
- Batch-first: only one progress bar and single output box.
- Output formats:
  * Plain URLs
  * HTML <img>, <a>, <video>
  * Markdown (image or link)
  * BBCode [img]
  * Custom template with placeholders ({url}, {name}, {base}, {ext}, {i})

----------------------------------------------------------------------
CONFIGURATION
----------------------------------------------------------------------

Edit CONFIG section at the top of `wasabi-direct-uploader.php`:

$WASABI_REGION       = '';   // e.g. 'ap-southeast-1'
$WASABI_BUCKET       = '';   // e.g. 'my.bucket.name'
$AWS_ACCESS_KEY      = '';   // your Wasabi Access Key
$AWS_SECRET_KEY      = '';   // your Wasabi Secret Key
$CDN_BASE            = '';   // optional CDN URL, e.g. 'https://cdn.example.com'
$EXPIRES_SECONDS     = 3600; // signed URL lifetime (seconds)
$ALLOW_MIME          = [];   // [] = allow all, or restrict MIME types
$FORCE_LOWERCASE     = true; // normalize filenames to lowercase
$ADD_RANDOM_PREFIX   = true; // add random hex prefix to avoid collisions

----------------------------------------------------------------------
USAGE
----------------------------------------------------------------------

1. Place `wasabi-direct-uploader.php` on a PHP-enabled server (HTTPS recommended).
2. Edit CONFIG section with your Wasabi region, bucket, and keys.
3. Ensure your bucket has a proper **CORS configuration** to allow
   PUT and GET from your server's origin.

   Example CORS (Bucket → CORS settings):
   {
     "CORSRules": [
       {
         "AllowedOrigins": ["*"],
         "AllowedMethods": ["PUT", "GET", "HEAD"],
         "AllowedHeaders": ["*"],
         "ExposeHeaders": ["ETag"],
         "MaxAgeSeconds": 3000
       }
     ]
   }

4. Open the tool in a browser:
   - Drag & drop files or choose them via file picker.
   - Adjust prefix, output format, or template.
   - Click "Upload".
   - Copy the generated output.

----------------------------------------------------------------------
NOTES
----------------------------------------------------------------------

- This tool presigns upload URLs server-side and uploads directly from
  the browser to Wasabi. Your server never stores the files.
- Use HTTPS to protect your access key and presigned URLs.
- For production, consider restricting allowed MIME types.
- Works with any bucket name, including names with dots.

----------------------------------------------------------------------
CREDIT
----------------------------------------------------------------------

© Init HTML
https://inithtml.com
