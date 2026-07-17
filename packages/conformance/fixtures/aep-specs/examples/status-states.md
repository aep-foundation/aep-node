# Status States

This example shows representative Status responses for Agent identity states
beyond the active case.

## Pending

```json
{
  "requirements_pending": ["contact.email"],
  "since": "2026-06-28T12:00:00Z",
  "status": "pending"
}
```

## Unavailable

```json
{
  "since": "2026-06-28T12:10:00Z",
  "status": "unavailable"
}
```

## Suspended

```json
{
  "owner_action_required": "true",
  "requirements_pending": ["owner.review"],
  "since": "2026-06-28T12:15:00Z",
  "status": "suspended"
}
```

## Terminated

```json
{
  "since": "2026-06-28T12:20:00Z",
  "status": "terminated"
}
```

## Rejected

```json
{
  "since": "2026-06-28T12:25:00Z",
  "status": "rejected"
}
```
