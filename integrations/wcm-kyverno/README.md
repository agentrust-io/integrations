# WCM → Kyverno ClusterPolicy

Generates the Kubernetes admission rules a WCM-governed workload needs before it
is deployable at all. It is a **precondition** gate, not an attestation gate.

## Read this before anything else

The obvious idea is to make Kyverno check the pod's image digest against
`release_policy.required_serving_image.accepted_measurements`. **That would be
wrong**, and this generator refuses to do it.

Those measurements are *launch measurements*: the value an enclave reports in its
quote as `CpuQuote.serving_image_measurement`, produced by the
confidential-computing platform over the loaded workload. An OCI image digest is
a hash of a tarball in a registry. They are different numbers over different
bytes.

Comparing them would fail every time. The worse outcome is someone "fixing" the
mismatch by putting registry digests into the manifest field the key broker
compares against a quote, which destroys the binding the whole protocol rests on.

Verifying a launch measurement needs a quote, a nonce and a trust store. Kyverno
has none of those at admission time. That check belongs to the key broker, at
release time, and cannot be moved earlier. The generated YAML says so in a header
comment, so an operator reading the policy in a cluster sees the boundary without
finding this README.

## What it does enforce, and why that is worth having

WCM's threat model names an operator with software access on the host. Most of
what such an operator needs is granted by the pod spec. A cluster that permits
those has given away the software half of the guarantee before any key is
released, and none of it requires a quote to check.

| Rule | Closes |
|---|---|
| `require-confidential-runtime-class` | Workload silently landing on an ordinary node |
| `deny-process-inspection` | `privileged`, `SYS_PTRACE`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO` |
| `deny-host-namespaces` | `hostPID`, `hostIPC`, `hostNetwork`, `shareProcessNamespace` |
| `require-digest-pinned-images` | A tag resolving to different bytes than the ones reviewed |
| `require-manifest-hash-annotation` | A pod claiming custody governance it is not under |
| `require-confidential-gpu` | Missing GPU request or a node not in CC mode, when the manifest asks for a GPU measurement |
| `require-dedicated-node` | Emitted only when `tenancy: dedicated` |

The manifest-hash annotation is the manifest's canonical hash, so changing any
signed field changes the required value. A pod cannot be moved between custody
agreements by editing a label.

## What cannot be enforced here

Reproduced verbatim in the generated YAML:

| Manifest field | Enforced where instead |
|---|---|
| `required_serving_image.accepted_measurements` | Key broker, at release, against a nonce and a trust store |
| `required_assurance_tier` | Asserted by a signed quote; admission sees a pod spec |
| `attestation_cadence` | The Layer 3 lease loop inside the workload; admission runs once, at creation |
| `revocation_authority` | Release time and runtime. Revoking weights does not delete a running pod, it stops the next release and triggers wipe-on-lapse |
| `physical_hardening` | A datacentre control. No cluster policy can see whether the rack has a tamper-evident enclosure |
| `memory_fingerprint_challenge` | Key broker, against enclave-produced evidence. The CLI warns on stderr when a manifest requires it |

`require-dedicated-node` is honest about its own limit in its message: Kyverno
cannot observe what else is scheduled beside a pod, so it enforces the
declaration, not the outcome. Pair it with a `NoSchedule` taint for the outcome
to follow.

## Runtime class names

Defaults are the confidential-containers names:

| WCM platform | Runtime classes |
|---|---|
| `amd-sev-snp` | `kata-qemu-snp`, `kata-cc` |
| `intel-tdx` | `kata-qemu-tdx`, `kata-cc` |
| `nvidia-cc-gpu` | none: it is a device requirement, not a VM runtime class |

Clusters rename these. A cluster using different names will reject every pod
until `--runtime-class` is supplied, which is the correct failure direction for a
policy generator.

## Run it

```bash
pip install weight-custody-manifest

python wcm_kyverno.py manifest.json --name custody-example > policy.yaml
kubectl apply -f policy.yaml
```

Useful flags:

```bash
--namespace serving                        # restrict; repeatable
--selector app=inference                   # what marks a governed pod; repeatable
--runtime-class amd-sev-snp=my-cc-class    # repeatable
--audit                                    # measure blast radius first
```

`--audit` emits `validationFailureAction: Audit`, and the header then says the
policy blocks nothing, because a policy left in Audit is a policy that enforces
nothing and it should not be possible to forget that.

The default selector is `wcm.agentrust-io.com/governed: "true"`. A policy
matching every pod in the cluster would be the wrong shape: most workloads are
not serving custody-governed weights, and a rule that blocked them would be
switched off within the day.

## No PyYAML dependency

The emitter quotes every scalar. Verbose, but it sidesteps every YAML coercion
trap: `on` becoming `True`, `1.10` becoming a float, a leading `*` starting an
alias. A policy that changed meaning between generation and apply would be the
worst possible bug here. Tests parse the output with real PyYAML when it is
available.

## Scope

Deployment preconditions only. Confidential computing does not hold against an
operator who physically owns the hardware (WCM `SPEC.md` §3.6), and a cluster
policy does not change that in either direction.

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
