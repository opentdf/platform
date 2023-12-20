
# Issues

- https://github.com/protocolbuffers/protobuf/issues/10329#issuecomment-1648792288

There are issues with the import statements when generating the python code. This requires you to use the protoletariat tool which will fix the import statements after generation. 

https://github.com/cpcloud/protoletariat

## Generation
  
  ```bash
  buf generate ../../proto
  protol --create-package --in-place --python-out gen buf ../../proto
  ```
