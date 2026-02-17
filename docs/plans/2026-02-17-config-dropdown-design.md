# Config Dropdown Picker Design

## Concept
When a config field has a known set of valid values, pressing Enter opens a small inline dropdown list instead of entering text edit mode. Arrow keys navigate, Enter confirms, Esc cancels.

## FieldType Changes
- New variant: `Enum(Vec<String>)` — finite set of valid options
- `Bool` removed — becomes `Enum(vec!["true", "false"])`

## Dropdown State
```rust
pub struct DropdownState {
    pub field_index: usize,
    pub options: Vec<String>,
    pub selected: usize,
}
```
App field: `pub config_dropdown: Option<DropdownState>`

## Interaction Flow
1. Enter on Enum field → dropdown opens, current value pre-selected
2. ↑↓ moves selection, Enter confirms, Esc cancels
3. On confirm: apply value, close dropdown

## Rendering
- Small bordered box overlaying field list at the field's Y position
- Width: max option length + 4, Height: option count + 2
- Selected option in reverse video
- Right-aligned to the field value area

## Field Mapping
| Field | Options |
|---|---|
| All `enabled`, `watch_all_users` | `true`, `false` |
| `min_alert_level`, `min_slack_level` | `info`, `warn`, `crit` |
| `netpolicy.mode` | `allow`, `deny`, `disabled` |

## Changes Required
- `get_section_fields`: return `Enum(vec![...])` for booleans and known enums
- `handle_config_key`: Enter on Enum opens dropdown; new dropdown-active key handler
- `render_config_tab`: render dropdown overlay when active
- Remove `FieldType::Bool` entirely
