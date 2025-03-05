# AWS policies for use in Compliance Framework AWS Plugin

## Requirements

Install [opa](https://www.openpolicyagent.org/docs/latest/#running-opa) for testing & building the bundles.

## Testing


```shell
opa test policies
```

## Bundling

Policies are built into bundle to make distribution easier. 

You can easily build the policies by running 
```shell
opa build -b policies -o dist/bundle.tar.gz
```

## Running policies locally