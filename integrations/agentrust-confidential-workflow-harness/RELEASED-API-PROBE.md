# Experimental released-protocol interoperability probe

This isolated, deterministic probe executes published cmcp-runtime 0.7.0 MCPGateway.intercept_tool_call and ca2a-runtime 0.4.0 emit_dag/trace_record_hash APIs. Synthetic transaction ID and nonce are passed into the call and software-mode record context. The two signing keys are ephemeral test keys.

To reproduce, install exactly cmcp-runtime==0.7.0 and ca2a-runtime==0.4.0 in an isolated Python environment, then run unittest discovery in the integration's tests directory with the integration directory on PYTHONPATH.

Claim: component API interoperability only. The probe does not execute models or tools; actual_dispatches is zero. It does not prove independent peer receipt, live deployment, hardware TEE, independent key custody or composed confidentiality acceptance. The synthetic trace hashes do not establish external trust.

Issue #199 remains open pending real tool and peer transport adapters, independent observation at each boundary, paired refusal and mutation tests for the composed workflow, and externally operated live evidence. Do not reuse component pass results as a composed or hardware assurance verdict.
