```text
{
  parentId: options.parentId,
  reason: 'forward',

  from: options.sender,
  to: options.recipient,

  // targets: forwardTargets.size
  //     ? Array.from(forwardTargets).map(row => ({
  //         type: row[1].type,
  //         value: row[1].value
  //     }))
  //     : false,

  targets: options.targets,

  interface: 'forwarder'
}
```