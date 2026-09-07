# Architecture

Source (read-only)
 -> partition map
 -> filesystem detector
 -> provider
 -> geometry validation
 -> metadata parser
 -> relationship validator
 -> directory graph
 -> extent map
 -> health report
 -> JSON model

## Common object model

FilesystemVolume
  geometry
  metadata
  health

FsObject
  object id
  type
  parent
  name
  size
  timestamps
  flags
  extents

Extent
  logical offset
  physical offset
  length

## Recovery principle

A filesystem object is accepted only when enough independent structure agrees:
boot/superblock geometry + metadata structure + bounds + relationships.

If structure is incomplete, the provider reports a degraded/partial state
instead of silently manufacturing a path or extent.
