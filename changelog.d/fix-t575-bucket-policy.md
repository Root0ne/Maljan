### Security

- **The object store's bucket is left private, and the health check fails one an anonymous caller is let into (T-575).** Every new bucket was meant to get an anonymous-deny policy, but MinIO refuses its `aws:PrincipalType` condition (`MalformedPolicy`), so the call only logged a warning and no bucket carried it. A bucket with no policy is how MinIO refuses an anonymous caller (checked live: an anonymous read, write, listing and bucket HEAD are refused, the platform's keys work), so a fresh bucket now gets no policy and the log says so. `/health?deep=true` asks the bucket anonymously for a listing and a read, and reads its policy for any statement that allows anyone; a bucket that lets an anonymous caller in fails the `minio` component, and the API log names what it allows. A bucket that carries a deny policy from elsewhere is left as it is.
- **The MinIO container runs with no Linux capability and no way to gain one.** The `minio` service drops every capability and sets `no-new-privileges`; it starts, stays healthy and reads and writes an existing `minio_data` volume with them. It still runs as root, which owns that volume.

### Documentation

- **The deployment page's Qdrant row says what its pin is held to:** within one minor release of the locked client, rather than matching it.
