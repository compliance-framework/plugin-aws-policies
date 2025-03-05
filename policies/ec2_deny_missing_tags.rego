# Ensure that json has "hello": "world" in it.
#
# METADATA
# title: Verify AWS Controls
# description: Verifies that the correct AWS controls are in place.
# custom:
#   controls:
#     - None
#   schedule: "* * * * * *"
package compliance_framework.template.aws

violation[{
    "title": "Check to ensure correct tags are set on EC2 Instances",
    "description": "Ensure that the best practice tags are assigned to the EC2 instance",
    "remarks": "Ensure the following tags are set on the EC2 instance: Environment, Owner, compliance, confidentiality, backup, role."
}] if {
    not tag_exists("environment")
    not tag_exists("role")
}

tag_exists(tag_name) if {
    some tag in input.Tags
    tag.Key == tag_name
}