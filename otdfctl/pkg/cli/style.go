//nolint:mnd // styling is magic
package cli

import "github.com/charmbracelet/lipgloss"

type Color struct {
	Foreground lipgloss.CompleteAdaptiveColor
	Background lipgloss.CompleteAdaptiveColor
}

var colorRed = Color{
	Foreground: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#FF0000",
			ANSI256:   "9",
			ANSI:      "1",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#FF0000",
			ANSI256:   "9",
			ANSI:      "1",
		},
	},
	Background: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#FFD2D2",
			ANSI256:   "224",
			ANSI:      "7",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#da6b81",
			ANSI256:   "52",
			ANSI:      "4",
		},
	},
}

var colorOrange = Color{
	Foreground: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#FFA500",
			ANSI256:   "214",
			ANSI:      "3",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#FFA500",
			ANSI256:   "214",
			ANSI:      "3",
		},
	},
	Background: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#FFEBCC",
			ANSI256:   "230",
			ANSI:      "7",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#663300",
			ANSI256:   "94",
			ANSI:      "4",
		},
	},
}

//lint:ignore U1000 // not used yet
var colorYellow = Color{
	Foreground: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#FFFF00",
			ANSI256:   "11",
			ANSI:      "3",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#FFFF00",
			ANSI256:   "11",
			ANSI:      "3",
		},
	},
	Background: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#FFFFE0",
			ANSI256:   "229",
			ANSI:      "7",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#666600",
			ANSI256:   "100",
			ANSI:      "4",
		},
	},
}

func ColorYellow() Color {
	return colorYellow
}

var colorGreen = Color{
	Foreground: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#008000",
			ANSI256:   "28",
			ANSI:      "2",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#008000",
			ANSI256:   "28",
			ANSI:      "2",
		},
	},
	Background: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#D2FFD2",
			ANSI256:   "157",
			ANSI:      "7",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#29cf68",
			ANSI256:   "22",
			ANSI:      "4",
		},
	},
}

var colorBlue = Color{
	Foreground: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#0000FF",
			ANSI256:   "21",
			ANSI:      "4",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#3355d3",
			ANSI256:   "21",
			ANSI:      "4",
		},
	},
	Background: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#7d8ad1",
			ANSI256:   "189",
			ANSI:      "7",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#85a2d0",
			ANSI256:   "17",
			ANSI:      "4",
		},
	},
}

var colorIndigo = Color{
	Foreground: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#4B0082",
			ANSI256:   "57",
			ANSI:      "5",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#4B0082",
			ANSI256:   "57",
			ANSI:      "5",
		},
	},
	Background: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#E6E6FA",
			ANSI256:   "225",
			ANSI:      "7",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#2A0033",
			ANSI256:   "55",
			ANSI:      "4",
		},
	},
}

//lint:ignore U1000 // not used yet
var colorViolet = Color{
	Foreground: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#EE82EE",
			ANSI256:   "13",
			ANSI:      "5",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#EE82EE",
			ANSI256:   "13",
			ANSI:      "5",
		},
	},
	Background: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#F5E6FF",
			ANSI256:   "189",
			ANSI:      "7",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#550055",
			ANSI256:   "90",
			ANSI:      "4",
		},
	},
}

var colorGray = Color{
	Foreground: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#808080",
			ANSI256:   "244",
			ANSI:      "7",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#808080",
			ANSI256:   "244",
			ANSI:      "7",
		},
	},
	Background: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#F2F2F2",
			ANSI256:   "231",
			ANSI:      "7",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#333333",
			ANSI256:   "235",
			ANSI:      "0",
		},
	},
}

var colorWhite = Color{
	Foreground: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#FFFFFF",
			ANSI256:   "15",
			ANSI:      "7",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#FFFFFF",
			ANSI256:   "15",
			ANSI:      "7",
		},
	},
	Background: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#F5F5F5",
			ANSI256:   "231",
			ANSI:      "7",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#333333",
			ANSI256:   "235",
			ANSI:      "0",
		},
	},
}

var colorBlack = Color{
	Foreground: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#000000",
			ANSI256:   "0",
			ANSI:      "0",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#000000",
			ANSI256:   "0",
			ANSI:      "0",
		},
	},
	Background: lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{
			TrueColor: "#E0E0E0",
			ANSI256:   "248",
			ANSI:      "7",
		},
		Dark: lipgloss.CompleteColor{
			TrueColor: "#121212",
			ANSI256:   "235",
			ANSI:      "0",
		},
	},
}

////////

var statusBarStyle = lipgloss.NewStyle().
	Padding(1).
	MarginRight(1)

var styleSuccessStatusBar = lipgloss.NewStyle().
	Inherit(statusBarStyle).
	Foreground(colorBlack.Foreground).
	Background(colorGreen.Background).
	Padding(0, 2).
	MarginRight(1).
	MarginBottom(1)

var styleErrorStatusBar = lipgloss.NewStyle().
	Inherit(statusBarStyle).
	Foreground(colorBlack.Foreground).
	Background(colorRed.Background).
	Padding(0, 3).
	PaddingRight(3).
	MarginRight(1)

//lint:ignore U1000 // not used yet
var styleNoteStatusBar = lipgloss.NewStyle().
	Inherit(statusBarStyle).
	Foreground(colorYellow.Foreground).
	Background(colorYellow.Background)

var styleDebugStatusBar = lipgloss.NewStyle().
	Inherit(statusBarStyle).
	Foreground(colorBlack.Foreground).
	Background(colorIndigo.Background).
	PaddingRight(3)

var styleWarningStatusBar = lipgloss.NewStyle().
	Inherit(statusBarStyle).
	Foreground(colorOrange.Foreground).
	Background(colorOrange.Background).
	Padding(0, 2).
	MarginRight(1)

var footerLabelStyle = lipgloss.NewStyle().
	Inherit(statusBarStyle).
	Foreground(colorWhite.Foreground).
	Background(colorBlue.Background).
	Padding(0, 2)

var footerTextStyle = lipgloss.
	NewStyle().
	Background(colorGray.Background).
	PaddingLeft(1).
	Inherit(statusBarStyle)

// Table

var styleTableBorder = lipgloss.CompleteAdaptiveColor{
	Light: colorIndigo.Background.Dark,
	Dark:  colorIndigo.Background.Light,
}

var styleTable = lipgloss.
	NewStyle().
	Foreground(lipgloss.CompleteAdaptiveColor{
		Light: colorBlack.Foreground.Light,
		Dark:  colorWhite.Foreground.Dark,
	}).
	BorderForeground(styleTableBorder)

// Text

//lint:ignore U1000 // not used yet
var styleText = lipgloss.
	NewStyle().
	Foreground(lipgloss.CompleteAdaptiveColor{
		Light: colorBlack.Foreground.Light,
		Dark:  colorWhite.Foreground.Dark,
	})

//lint:ignore U1000 // not used yet
var styleTextBold = lipgloss.
	NewStyle().
	Foreground(lipgloss.CompleteAdaptiveColor{
		Light: colorBlack.Foreground.Light,
		Dark:  colorWhite.Foreground.Dark,
	}).
	Bold(true)
