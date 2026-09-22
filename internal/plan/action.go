package plan

// Action is the normalised form of a resource change's actions array.
type Action int

const (
	NoOp Action = iota
	Create
	Read
	Update
	Delete
	Replace
	Forget
	Unknown
)

var actionNames = [...]string{
	NoOp:    "no-op",
	Create:  "create",
	Read:    "read",
	Update:  "update",
	Delete:  "delete",
	Replace: "replace",
	Forget:  "forget",
	Unknown: "unknown",
}

func (a Action) String() string {
	if a < 0 || int(a) >= len(actionNames) {
		return "unknown"
	}
	return actionNames[a]
}

// MapActions converts a Terraform actions array to an Action.
// createBeforeDestroy is true only for ["create","delete"].
// ok is false when the combination is not recognised; the Action is then Unknown.
func MapActions(actions []string) (a Action, createBeforeDestroy bool, ok bool) {
	switch len(actions) {
	case 1:
		switch actions[0] {
		case "no-op":
			return NoOp, false, true
		case "create":
			return Create, false, true
		case "read":
			return Read, false, true
		case "update":
			return Update, false, true
		case "delete":
			return Delete, false, true
		case "forget":
			return Forget, false, true
		}
	case 2:
		switch {
		case actions[0] == "delete" && actions[1] == "create":
			return Replace, false, true
		case actions[0] == "create" && actions[1] == "delete":
			return Replace, true, true
		}
	}
	return Unknown, false, false
}
