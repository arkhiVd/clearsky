"""Import every detector module so it registers itself."""

from clearsky.detectors import (  # noqa: F401
    ebs,
    ec2_idle,
    ec2_stopped,
    eks,
    elb_rds,
    network,
    logs_retention,
    s3_hygiene,
    security_data,
    security_iam,
    security_net,
    unused_eip,
)
