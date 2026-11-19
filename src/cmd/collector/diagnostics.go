package main

import "errors"

// privateDiagnosticf is deliberately silent in all builds. This is not a
// redaction regex: arbitrary byte/string/error arguments are never formatted.
// There is no tag, flag or environment variable that can restore this sink.
func privateDiagnosticf(_ string, _ ...any) {}

func productionDiagnosticsPolicy() error {
	if *flagNoFilter || *flagAllowAC {
		return errors.New("[GS-FILTER 5] 生产版禁止关闭目标过滤或绕过安全闸门")
	}
	if *flagIPC || *flagDump != "" || *flagDiagnose != "" || *flagLogFile != "" || *flagUIFreeze != 0 || *flagHintsInfo {
		return errors.New("生产版禁止敏感诊断导出：ipc/dump/diagnose/logfile/ui-freeze/hints-info")
	}
	return nil
}
