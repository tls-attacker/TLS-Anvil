package logging

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"path"
	"runtime"
	"uploader/src/config"
)

var Logger *logrus.Logger

func init() {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:             true,
		DisableLevelTruncation:    false,
		PadLevelText:              true,
		CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
			function = ""
			file = fmt.Sprintf(" %s:%d", path.Base(frame.File), frame.Line)
			return
		},
		TimestampFormat: "15:04:05.000",
	})

	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(config.GetConfig().LogLevel)
	logrus.SetReportCaller(true)

	Logger = logrus.StandardLogger()

}
