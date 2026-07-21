# Rego policy for core AWS S3 bucket checks.

package policyforge.aws.core

# PF-AWS-001: S3 bucket must not use a public-read(-write) canned ACL
deny[msg] {
	input.type == "s3_bucket"
	input.attributes.acl == "public-read"
	msg := sprintf("PF-AWS-001: S3 bucket %q uses public-read ACL", [input.name])
}

deny[msg] {
	input.type == "s3_bucket"
	input.attributes.acl == "public-read-write"
	msg := sprintf("PF-AWS-001: S3 bucket %q uses public-read-write ACL", [input.name])
}

severity["PF-AWS-001"] = "HIGH"
