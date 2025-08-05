# Region_map.d Directory Information


Starting with SOCA `25.x.y` the SOCA installer will read YAML files from a `region_map.d` filesystem tree in order to lookup AMIs used for the environment.


This directory structure will be processed in a lexicographically sorted manner so that site-local over-rides can take places from the SOCA supplied defaults (files starting with `000`).

This will minimize future problems and still allow for SOCA defaults to be updated/shipped with each version while preserving site-local changes.


#  SOCA Defaults

SOCA defaults (potentially updated with each version of SOCA) are contained in the `aws/000-<region>.yaml` files. These should not be edited directly as they are updated with each SOCA version.


# Site Local Specifications

In order to make use of a different AMI - create/update files in the format `aws/nnn-<region>.yaml` , where `nnn` is numerically greater than `000` (the SOCA defaults).

For example, for the `us-east-1` region, this could be `001-us-east-1.yaml`, etc.

The format of the YAML file should match the expected structure or the files will not be properly read.

Structure:

```yaml
region:
  architecture:
    baseos: AMI-ID
```


Example:

```yaml
us-east-1:
  x86_64:
    amazonlinux2023: ami-1234567890abcdef
```

In this example - the AMI `ami-1234567890abcdef` will be used for `us-east-1` `x86_64` architecture systems running the `amazonlinux2023` base OS.

These values will over-ride the SOCA supplied defaults.

*NOTE* - You can supply multiple regions per file. Just make sure the naming / numbering convention would place the file *AFTER* the SOCA default file for a given region, or after all regions.

For example - `999-my-ami-defaults.yaml` can contain:

```yaml
us-east-1:
  x86_64:
    amazonlinux2023: ami-12345678
us-east-2:
  x86_64:
    amazonlinux2023: ami-feedc0ffee

```

This will apply the configured AMIs to the two different regions.

Make sure to observe the proper format and YAML indenting.


