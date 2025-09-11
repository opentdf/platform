package identifier

import "strings"

func BreakOblFQN(fqn string) (string, string) {
	nsFQN := strings.Split(fqn, "/obl/")[0]
	parts := strings.Split(fqn, "/")
	oblName := strings.ToLower(parts[len(parts)-1])
	return nsFQN, oblName
}

func BreakOblValFQN(fqn string) (string, string, string) {
	parts := strings.Split(fqn, "/value/")
	nsFQN, oblName := BreakOblFQN(parts[0])
	oblVal := strings.ToLower(parts[len(parts)-1])
	return nsFQN, oblName, oblVal
}

func BuildOblFQN(nsFQN, oblName string) string {
	return nsFQN + "/obl/" + strings.ToLower(oblName)
}

func BuildOblValFQN(nsFQN, oblName, oblVal string) string {
	return BuildOblFQN(nsFQN, oblName) + "/value/" + strings.ToLower(oblVal)
}
