package compliance_framework.template.aws._deny_missing_tags

required_tags := ["Environment","Security","Compliance","Application","Cost Center","Project","Owner","Name",]

violation[{
    "title": "Check to ensure correct tags are set on EC2 Instances",
    "description": sprintf("Instance '%v' is missing required tags: %v", [instance.InstanceID, missing_tags]),
    "remarks": "Ensure the following tags are set on the EC2 instance: Environment, Owner, compliance, confidentiality, backup, role."
}] if {
    some instance in input.instances
    missing_tags := {tag | tag := required_tags[_]; not tag_exists(instance.Tags, tag)}
    count(missing_tags) > 0
}

tag_exists(tags, tag_name) if {
    some tag in tags
    lower(tag.Key) == tag_name
}
