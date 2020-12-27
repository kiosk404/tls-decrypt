/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2020/12/27
**/
package utils

import (
	"fmt"
	"github.com/rs/zerolog"
	"os"
	"strings"
	"time"
)

var Logging zerolog.Logger

func init() {
	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	output.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
	}
	output.FormatMessage = func(i interface{}) string {
		return fmt.Sprintf("** %s **", i)
	}
	output.FormatFieldName = func(i interface{}) string {
		return fmt.Sprintf("%s:", i)
	}
	output.FormatFieldValue = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("%s", i))
	}

	Logging = zerolog.New(output).With().Timestamp().Caller().Logger()
	Logging = Logging.Output(zerolog.ConsoleWriter{Out: os.Stderr})

}

func SetDebugLevel() {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
}

func SetQuietLevel() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}


