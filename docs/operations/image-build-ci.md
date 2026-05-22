# Image Build CI Operations

`Build` is the fast required workflow. `Image Build` is the heavy artifact
producer for nightly, manual, `main` push, and release evidence.

## Manual Run

```bash
gh workflow run "Image Build" --ref main
```

Use the resulting run ID as `source_run_id` when starting `Release Preflight`.
Release-candidate preflight accepts only a successful protected `main` push
`Image Build` run; manual runs are for diagnostics and technical dry runs.

## Nightly Failure Triage

1. Open the failed `Image Build` run and inspect the final job summary first.
   It lists critical path, cache hit/miss evidence, slow package timing, and
   artifact digests.
2. If `build-payload` fails on base identity, compare the downloaded
   `usb-installer-base.json` with the payload job's expected matrix/source/key
   digests. Do not reuse a mismatched base by hand.
3. If payload packaging exceeds budget, inspect
   `<defconfig>.payload-package.json` timing before changing the budget.
4. If Buildroot timing regresses, keep the run as evidence and compare package
   timing across the last successful heavy runs before adding a fail gate.

## Cache Miss Notes

Downloads and ccache may reduce runtime, but mutable Buildroot output cache is
not a release input. A cache miss is acceptable when the immutable evidence and
artifact digests validate. A cache hit must never substitute for manifest or
attestation validation.

## Release Checklist

- `Image Build` completed successfully for the exact source SHA.
- The run published `image-build-contract`, release image artifacts,
  installer artifacts, build logs, performance evidence, payload inputs,
  payload package evidence, and USB installer base evidence.
- GitHub artifact attestations verify against
  `.github/workflows/image-build.yml@refs/heads/main`.
- `Release Preflight` validates the image build contract and creates a signed
  `suderra.release-ingress.v1` manifest.
