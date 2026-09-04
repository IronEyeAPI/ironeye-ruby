# IronEye for Ruby

The official Ruby client for the [IronEye](https://ironeye.org) API: document
analysis over bytes you send, and normalised collection from public sources,
behind one key.

```sh
gem install ironeye
```

## Features

- Every analysis route, the async job path with `await_job`, the collection
  catalogue and the data-subject-rights endpoints.
- One exception class per refusal family, each carrying the server's verdict.
- Retries on the server's own `retryable` flag, honouring `Retry-After`.
- Standard library only: `Net::HTTP` and `JSON`, no gem tree behind it.
- Takes any `Logger`. No credential, no payload.

Full documentation, including every endpoint and every option, is at
**https://ironeye.org/docs/sdk/ruby**.

---

Direct Softworks · [MIT](LICENSE) · issues and pull requests welcome
