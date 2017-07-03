package secprofile

/* Add capability if not present to capability set */
func addCapToList(capList []string, capToAdd string) []string {
	for _, cap := range capList {
		if cap == capToAdd {
			return capList
		}
	}

	return append(capList, capToAdd)
}

/* Remove capability if present from capability set */
func removeCapFromList(capList []string, capToRemove string) []string {
	for index, cap := range capList {
		if cap == capToRemove {
			return append(capList[:index], capList[index+1:]...)
		}
	}

	return capList
}
