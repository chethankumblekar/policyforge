resource "aws_s3_bucket" "logs" {
  bucket = "example-logs-bucket"
  acl    = "public-read"
}

resource "aws_security_group_rule" "allow_all_ingress" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-example"
}
