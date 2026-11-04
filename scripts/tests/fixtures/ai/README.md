# Synthetic AI assessment examples

[Seven example plans](AI%20Agent%20Assessment%20Examples.json) exercise the [assessment schema](../../../../assessment/ai/AI%20Agent%20Assessment%20Plan.schema.json) and [applicability matrix](../../../../assessment/ai/AI%20Agent%20Assessment%20Applicability.json): public MCP HTTP, Android stdio, Android AppFunctions, desktop local, fixed REST, multimodal and hybrid boundaries.

These are test fixtures, not collected product evidence, approved production-equivalent fixtures or authorized assessments. Placeholder evidence and pending approvals cannot establish a pass. The [Agent Test Guide](../../../../AI%20Profile/AI%20Agent%20Test%20Guide.md#assessment-plans-and-records) explains how plans and records are used.

```sh
python3 scripts/agent_assessment_policy_validate.py --example hybrid --expand
python3 -m unittest discover -s scripts/tests -p test_agent_assessment_policy.py
```
