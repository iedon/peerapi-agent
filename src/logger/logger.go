package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Level represents log levels
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
	FATAL
)

func (l Level) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel converts a string level to Level type
func ParseLevel(level string) Level {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return DEBUG
	case "INFO":
		return INFO
	case "WARN":
		return WARN
	case "ERROR":
		return ERROR
	case "FATAL":
		return FATAL
	default:
		return INFO // Default to INFO if unknown
	}
}

// Logger provides leveled logging with rotation support
type Logger struct {
	mu         sync.Mutex
	level      Level
	logger     *log.Logger
	logFile    *lumberjack.Logger
	consoleLog bool
}

// Config holds logger configuration
type Config struct {
	File           string
	MaxSize        int
	MaxBackups     int
	MaxAge         int
	Compress       bool
	ConsoleLogging bool
	Level          Level
}

// New creates a new logger instance
func New(cfg *Config) (*Logger, error) {
	if cfg == nil {
		cfg = &Config{
			File:           "peerapi-agent.log",
			MaxSize:        10,
			MaxBackups:     10,
			MaxAge:         30,
			Compress:       true,
			ConsoleLogging: true,
			Level:          INFO,
		}
	}

	// Set defaults
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 10
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 10
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 30
	}

	// Create lumberjack logger for file output with rotation
	logFile := &lumberjack.Logger{
		Filename:   cfg.File,
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	}

	// Define writers
	var writers []io.Writer
	writers = append(writers, logFile)

	if cfg.ConsoleLogging {
		writers = append(writers, os.Stdout)
	}

	multiWriter := io.MultiWriter(writers...)

	return &Logger{
		level:      cfg.Level,
		logger:     log.New(multiWriter, "", log.LstdFlags),
		logFile:    logFile,
		consoleLog: cfg.ConsoleLogging,
	}, nil
}

// SetLevel changes the logging level
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// Close closes the log file
func (l *Logger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

func (l *Logger) log(level Level, format string, v ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level < l.level {
		return
	}

	prefix := fmt.Sprintf("[%s] ", level.String())
	msg := fmt.Sprintf(format, v...)
	l.logger.Printf("%s%s", prefix, msg)

	if level == FATAL {
		os.Exit(1)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, v ...any) {
	l.log(DEBUG, format, v...)
}

// Info logs an info message
func (l *Logger) Info(format string, v ...any) {
	l.log(INFO, format, v...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, v ...any) {
	l.log(WARN, format, v...)
}

// Error logs an error message
func (l *Logger) Error(format string, v ...any) {
	l.log(ERROR, format, v...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(format string, v ...any) {
	l.log(FATAL, format, v...)
}

// Printf provides compatibility with standard logger interface
func (l *Logger) Printf(format string, v ...any) {
	l.Info(format, v...)
}

// Println provides compatibility with standard logger interface
func (l *Logger) Println(v ...any) {
	l.Info("%s", fmt.Sprint(v...))
}
