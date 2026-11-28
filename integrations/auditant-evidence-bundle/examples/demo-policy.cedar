// Demo policy for the example record, matching the fixture's "refund-limit" decision:
// a refund is allowed up to 100. An operator passes the policy file their deployment runs.
permit(principal, action == Action::"issue_refund", resource)
when { context.amount <= 100 };
