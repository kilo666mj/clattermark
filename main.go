package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kilo666mj/clattermark/keydb"
	"github.com/nxadm/tail"
)

var alertLog *log.Logger

const defaultSecretsPath = "/etc/clattermark/secrets.json"

func reopenLogFiles(logPath, alertPath string, currentLog, currentAlert **os.File) error {
	newLog, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("reopen main log: %w", err)
	}
	newAlert, err := os.OpenFile(alertPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		newLog.Close()
		return fmt.Errorf("reopen alert log: %w", err)
	}

	oldLog, oldAlert := *currentLog, *currentAlert
	log.SetOutput(newLog)
	alertLog.SetOutput(newAlert)
	*currentLog, *currentAlert = newLog, newAlert
	if err := oldLog.Close(); err != nil {
		log.Printf("close old main log: %v", err)
	}
	if err := oldAlert.Close(); err != nil {
		log.Printf("close old alert log: %v", err)
	}
	return nil
}

var (
	// Standard syslog: optional fractional seconds, separator before [pid] can be ": ", " ", or nothing.
	parseRegex = regexp.MustCompile(`(?P<tstmp>\d+-\d+-\d+T\d+:\d+:\d+(?:\.\d+)?\+\d+:\d+) (?P<host>[a-zA-Z0-9._\-]+) (?P<process>[a-zA-Z0-9/\-_.]+)(?::\s|\s)?\[(?P<pid>[^\]]*)\](?::)? (?P<text>.*)`)
	// nginx: process followed by embedded date, then [level] pid#tid: text.
	nginxRegex = regexp.MustCompile(`(?P<tstmp>\d+-\d+-\d+T\d+:\d+:\d+(?:\.\d+)?\+\d+:\d+) (?P<host>[a-zA-Z0-9._\-]+) (?P<process>[a-zA-Z0-9\-_.]+) \d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[(?P<pid>[^\]]+)\] \S+ (?P<text>.*)`)
	// stunnel/DhcpLFC: process followed by an uppercase level token then [pid].
	levelPidRegex = regexp.MustCompile(`(?P<tstmp>\d+-\d+-\d+T\d+:\d+:\d+(?:\.\d+)?\+\d+:\d+) (?P<host>[a-zA-Z0-9._\-]+) (?P<process>[a-zA-Z0-9\-_.]+) [A-Z][A-Z0-9]*\s*\[(?P<pid>[^\]]*)\](?::)? (?P<text>.*)`)
	// Fallback: no PID bracket (kernel, ansible, shell scripts).
	noPidRegex = regexp.MustCompile(`(?P<tstmp>\d+-\d+-\d+T\d+:\d+:\d+(?:\.\d+)?\+\d+:\d+) (?P<host>[a-zA-Z0-9._\-]+) (?P<process>[a-zA-Z0-9\-_.]+) (?P<text>.*)`)
)

type Config struct {
	MonFiles            []string                  `json:"mon_files"`
	Monitors            map[string]MonitorConfig  `json:"monitors"`
	KeyDB               KeyDBConfig               `json:"keydb"`
	Notifications       NotificationConfig        `json:"notifications"`
	Web                 WebConfig                 `json:"web"`
	StaleAlert          StaleAlertConfig          `json:"stale_alert"`
	DecisionService     DecisionServiceConfig     `json:"decision_service"`
	Processes           ProcessConfig             `json:"processes"`
	AlertDedup          AlertDedupConfig          `json:"alert_dedup"`
	Pipeline            PipelineConfig            `json:"pipeline"`
	IncidentAggregation IncidentAggregationConfig `json:"incident_aggregation"`
}

type PipelineConfig struct {
	Workers   int `json:"workers"`
	QueueSize int `json:"queue_size"`
}

func (c PipelineConfig) values() (int, int) {
	workers, queueSize := c.Workers, c.QueueSize
	if workers <= 0 {
		workers = 4
	}
	if queueSize <= 0 {
		queueSize = 1000
	}
	return workers, queueSize
}

type MonitorConfig struct {
	Search   string   `json:"search"`
	Excludes []string `json:"excludes"`
}

type monitor struct {
	name     string
	search   *regexp.Regexp
	excludes []string
}

func compileMonitors(configs map[string]MonitorConfig) ([]monitor, error) {
	names := make([]string, 0, len(configs))
	for name := range configs {
		names = append(names, name)
	}
	sort.Strings(names)

	monitors := make([]monitor, 0, len(names))
	for _, name := range names {
		cfg := configs[name]
		if strings.TrimSpace(cfg.Search) == "" {
			return nil, fmt.Errorf("monitor %q: search is required", name)
		}
		search, err := regexp.Compile(cfg.Search)
		if err != nil {
			return nil, fmt.Errorf("monitor %q: invalid search regex: %w", name, err)
		}
		monitors = append(monitors, monitor{name: name, search: search, excludes: cfg.Excludes})
	}
	return monitors, nil
}

type ProcessConfig struct {
	// Excludes is a list of regexes matched against the parsed process field;
	// a match drops the line for all monitors.
	Excludes []string `json:"excludes"`
}

type KeyDBConfig struct {
	Host     string `json:"host"`
	Password string `json:"password"`
}

type NotificationConfig struct {
	PrimaryURL   string `json:"primary_url"`
	SecondaryURL string `json:"secondary_url"`
	IconURL      string `json:"icon_url"`
	Channel      string `json:"channel"`
}

type WebConfig struct {
	ListenAddress string   `json:"listen_address"`
	Tokens        []string `json:"tokens"`
	APITokens     []string `json:"api_tokens"`
}

type StaleAlertConfig struct {
	VIP              string `json:"vip"`
	ThresholdMinutes int    `json:"threshold_minutes"`
}

type DecisionServiceConfig struct {
	Enabled              bool    `json:"enabled"`
	URL                  string  `json:"url"`
	Token                string  `json:"token"`
	TimeoutSeconds       int     `json:"timeout_seconds"`
	FailOpen             *bool   `json:"fail_open"`
	MinConfidence        float64 `json:"min_confidence"`
	FeedbackActionTarget string  `json:"feedback_action_target"`
}

type secretConfig struct {
	KeyDB struct {
		Password string `json:"password"`
	} `json:"keydb"`
	DecisionService struct {
		Token string `json:"token"`
	} `json:"decision_service"`
	Notifications struct {
		PrimaryURL   string `json:"primary_url"`
		SecondaryURL string `json:"secondary_url"`
	} `json:"notifications"`
	Web struct {
		Tokens    []string `json:"tokens"`
		APITokens []string `json:"api_tokens"`
	} `json:"web"`
}

func applySecretsFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read secrets file %s: %w", path, err)
	}
	var secrets secretConfig
	if err := json.Unmarshal(data, &secrets); err != nil {
		return fmt.Errorf("decode secrets file %s: %w", path, err)
	}
	if secrets.KeyDB.Password != "" {
		cfg.KeyDB.Password = secrets.KeyDB.Password
	}
	if secrets.DecisionService.Token != "" {
		cfg.DecisionService.Token = secrets.DecisionService.Token
	}
	if secrets.Notifications.PrimaryURL != "" {
		cfg.Notifications.PrimaryURL = secrets.Notifications.PrimaryURL
	}
	if secrets.Notifications.SecondaryURL != "" {
		cfg.Notifications.SecondaryURL = secrets.Notifications.SecondaryURL
	}
	if len(secrets.Web.Tokens) > 0 {
		cfg.Web.Tokens = append([]string(nil), secrets.Web.Tokens...)
	}
	if len(secrets.Web.APITokens) > 0 {
		cfg.Web.APITokens = append([]string(nil), secrets.Web.APITokens...)
	}
	return nil
}

func loadDynamicExcludes(keyDBInst *keydb.Keydb, attempts int, initialDelay time.Duration) (map[string][]string, error) {
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		var excludes map[string][]string
		excludes, err = keyDBInst.GetDynExcludes()
		if err == nil {
			return excludes, nil
		}
		if attempt < attempts {
			delay := initialDelay * time.Duration(1<<(attempt-1))
			log.Printf("keydb startup attempt %d/%d failed: %v; retrying in %s", attempt, attempts, err, delay)
			time.Sleep(delay)
		}
	}
	return nil, fmt.Errorf("keydb unavailable after %d attempts: %w", attempts, err)
}

func extractGroups(re *regexp.Regexp, line string) map[string]string {
	res := re.FindStringSubmatch(line)
	if res == nil {
		return nil
	}
	names := re.SubexpNames()
	parsed := make(map[string]string)
	for i, val := range res {
		if i == 0 || names[i] == "" || val == "" {
			continue
		}
		parsed[names[i]] = val
	}
	return parsed
}

func parseLine(line string) (map[string]string, error) {
	for _, re := range []*regexp.Regexp{nginxRegex, parseRegex, levelPidRegex, noPidRegex} {
		if parsed := extractGroups(re, line); parsed != nil {
			return parsed, nil
		}
	}
	log.Println("Unable to parse line:", line)
	return nil, errors.New("line did not match any regex")
}

func readConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	secretsPath := defaultSecretsPath
	if value, ok := os.LookupEnv("CLATTERMARK_SECRETS_FILE"); ok {
		secretsPath = value
	}
	if err := applySecretsFile(&cfg, secretsPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}
	return cfg, nil
}

func checkDynExcludesMulti(parsedLine map[string]string, excludes map[string][]string) bool {
	for excludeType, excludes := range excludes {
		for _, exclude := range excludes {
			if strings.Contains(parsedLine[excludeType], exclude) {
				return true
			}
		}
	}
	return false
}

// compileProcessExcludes compiles the process exclude regexes once at startup.
// Invalid patterns are logged and skipped rather than aborting.
func compileProcessExcludes(patterns []string) []*regexp.Regexp {
	var compiled []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			log.Printf("invalid process exclude regex %q: %v", p, err)
			continue
		}
		compiled = append(compiled, re)
	}
	return compiled
}

// matchesProcessExclude reports whether the parsed process field matches any
// configured process exclude regex.
func matchesProcessExclude(process string, excludes []*regexp.Regexp) bool {
	if process == "" {
		return false
	}
	for _, re := range excludes {
		if re.MatchString(process) {
			return true
		}
	}
	return false
}

// isNonActionableStructuredLine drops records whose incidental argument or URL
// text can contain monitor keywords without representing an application error.
func isNonActionableStructuredLine(parsed map[string]string) bool {
	process, text := parsed["process"], parsed["text"]
	if process == "snapd" && strings.Contains(text, "adjusting startup timeout by ") && strings.Contains(text, "(pessimistic estimate of ") {
		return true
	}
	return strings.HasPrefix(text, "ansible-") && strings.Contains(text, " Invoked with ")
}

func checkDynExcludesLine(line string, dynamicExcludes map[string][]string) bool {
	for _, exclude := range dynamicExcludes["text"] {
		if strings.Contains(line, exclude) {
			return true
		}
	}
	return false
}

func hasVIP(vip string) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Println("watchdog: error checking VIP:", err)
		return false
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.String() == vip {
			return true
		}
	}
	return false
}

func watchFileActivity(ctx context.Context, path string, staleCfg StaleAlertConfig, notifier *notificationClient, iconURL string, metrics *telemetry) {
	if staleCfg.VIP == "" || staleCfg.ThresholdMinutes == 0 {
		return
	}
	threshold := time.Duration(staleCfg.ThresholdMinutes) * time.Minute
	alerted := false
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !hasVIP(staleCfg.VIP) {
			alerted = false
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			log.Println("watchdog: stat error:", err)
			continue
		}
		if time.Since(info.ModTime()) > threshold {
			if !alerted {
				msg := fmt.Sprintf(":warning: No new logs in `%s` for >%d minutes — log pipeline may be broken", path, staleCfg.ThresholdMinutes)
				alertLog.Println(msg)
				card := tintwireCard{Version: 1, Title: "Log pipeline stale", Summary: fmt.Sprintf("No new logs for more than %d minutes", staleCfg.ThresholdMinutes), Severity: "critical", Source: "clattermark", Fields: []tintwireField{{Label: "Path", Value: path}}}
				if err := notifier.Send(card, "clattermark", "", msg, iconURL); err != nil {
					if metrics != nil {
						metrics.notificationFailures.Add(1)
					}
					log.Println("notification failed:", err)
				}
				alerted = true
			}
		} else {
			alerted = false
		}
	}
}

type alertEngine struct {
	monitors        []monitor
	dynamicExcludes *dynamicExcludesStore
	processExcludes []*regexp.Regexp
	notifier        *notificationClient
	iconURL         string
	decisionCfg     DecisionServiceConfig
	dedupCfg        AlertDedupConfig
	deduper         *alertDeduper
	decisionCache   *decisionCache
	incidents       *incidentAggregator
	metrics         *telemetry
}

func (e *alertEngine) checkLine(line string) {
	dynamicExcludesSnapshot := e.dynamicExcludes.Snapshot()
	for _, monitor := range e.monitors {
		if monitor.search.MatchString(line) {
			parsedLine, parseErr := parseLine(line)
			excludeLine := false
			if parseErr == nil {
				excludeLine = checkDynExcludesMulti(parsedLine, dynamicExcludesSnapshot)
				if !excludeLine && matchesProcessExclude(parsedLine["process"], e.processExcludes) {
					excludeLine = true
					log.Println("Excluding process exclude line:", line)
				}
				if !excludeLine && isNonActionableStructuredLine(parsedLine) {
					excludeLine = true
					log.Println("Excluding structured noise line:", line)
				}
			} else {
				excludeLine = checkDynExcludesLine(line, dynamicExcludesSnapshot)
			}
			if !excludeLine {
				for _, exclude := range monitor.excludes {
					if strings.Contains(line, exclude) {
						excludeLine = true
						break
					}
				}
			} else {
				log.Println("Excluding line:", line)
			}
			sendMMUsername := "clattermark"
			matterMsg := ""
			var card tintwireCard
			if !excludeLine {
				if parseErr == nil {
					card = logAlertCard(parsedLine)
					matterMsg = fmt.Sprintf(
						"**(%v,%v)** `"+"%v"+"` **(%v)** **(%v)**",
						parsedLine["process"],
						parsedLine["pid"],
						parsedLine["text"],
						parsedLine["host"],
						parsedLine["tstmp"],
					)
					sendMMUsername = fmt.Sprintf("clattermark - %v", parsedLine["host"])
				} else {
					card = rawLogAlertCard(line)
					matterMsg = fmt.Sprintf("`%v`", line)
				}
				fingerprint := alertFingerprint(line, parsedLine)
				decision, cached := e.decisionCache.GetOrEvaluate(fingerprint, func() alertDecision {
					started := time.Now()
					decision := shouldSendByDecisionService(e.decisionCfg, line, parsedLine, matterMsg)
					if e.metrics != nil {
						e.metrics.decisionCacheMisses.Add(1)
						if e.decisionCfg.Enabled {
							e.metrics.observeDecision(decision.Outcome, time.Since(started).Seconds())
						}
						if decision.ServiceFailed {
							e.metrics.decisionFailures.Add(1)
						}
					}
					return decision
				})
				if cached {
					if e.metrics != nil {
						e.metrics.decisionCacheHits.Add(1)
					}
				}
				if !decision.Send {
					continue
				}
				card.Actions = alertFeedbackActions(e.decisionCfg, decision, parsedLine)
				if rule := e.incidents.Match(line, parsedLine); rule != nil {
					update, err := e.incidents.Record(rule, parsedLine, parsedLine["text"])
					if err != nil {
						if e.metrics != nil {
							e.metrics.keyDBFailures.Add(1)
						}
						log.Printf("incident aggregation name=%q: %v; falling back to normal alert", rule.Name, err)
					} else if !update.Notify {
						log.Printf("incident event aggregated name=%q count=%d host=%q process=%q", rule.Name, update.Count, parsedLine["host"], parsedLine["process"])
						continue
					} else {
						card, matterMsg = incidentNotification(rule, update, parsedLine, parsedLine["text"])
						alertLog.Println(matterMsg)
						if err := e.notifier.Send(card, "clattermark", "", matterMsg, e.iconURL); err != nil {
							if e.metrics != nil {
								e.metrics.notificationFailures.Add(1)
							}
							e.incidents.Release(rule, update.Count)
							log.Println("incident notification failed:", err)
						}
						continue
					}
				}
				if e.dedupCfg.Enabled {
					if !e.deduper.Allow(fingerprint, decision.TTLSeconds) {
						log.Printf("deduplicated allowed alert: host=%q process=%q fingerprint=%s", parsedLine["host"], parsedLine["process"], fingerprint[:12])
						continue
					}
				}
				alertLog.Println(matterMsg)
				if err := e.notifier.Send(card, sendMMUsername, "", matterMsg, e.iconURL); err != nil {
					if e.metrics != nil {
						e.metrics.notificationFailures.Add(1)
					}
					if e.dedupCfg.Enabled {
						e.deduper.Forget(fingerprint)
					}
					log.Println("notification failed:", err)
				}
			}
		}
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	metrics := newTelemetry()
	configPath := flag.String("config", "/etc/clattermark/config.json", "path to configuration file")
	stateDir := flag.String("state-dir", "/var/lib/clattermark", "directory for logs and runtime state")
	flag.Parse()
	if err := os.MkdirAll(*stateDir, 0750); err != nil {
		log.Fatal(err)
	}
	pidFile := filepath.Join(*stateDir, "clattermark.pid")
	logPath := filepath.Join(*stateDir, "clattermark.log")
	alertPath := filepath.Join(*stateDir, "alerts.log")
	snapshotPath := filepath.Join(*stateDir, "dyn_excludes.json")
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
		log.Printf("Warning: could not write PID file %s: %v", pidFile, err)
	} else {
		defer os.Remove(pidFile)
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		log.Fatal(err)
		return
	}
	log.SetOutput(logFile)

	alertFile, err := os.OpenFile(alertPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		log.Fatal(err)
	}
	alertLog = log.New(alertFile, "", log.LstdFlags)

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGHUP)
		defer signal.Stop(sigs)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigs:
				if err := reopenLogFiles(logPath, alertPath, &logFile, &alertFile); err != nil {
					log.Println("Failed to reopen log files:", err)
				}
			}
		}
	}()

	cfg, err := readConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	monitors, err := compileMonitors(cfg.Monitors)
	if err != nil {
		log.Fatal(err)
	}
	notifier := newNotificationClient(cfg.Notifications.PrimaryURL, cfg.Notifications.SecondaryURL)
	notifier.defaultChannel = cfg.Notifications.Channel

	keyDBInst := keydb.New(cfg.KeyDB.Host, cfg.KeyDB.Password)
	deduper := newAlertDeduper(cfg.AlertDedup, &keyDBInst)
	incidents, err := newIncidentAggregator(cfg.IncidentAggregation, &keyDBInst, notifier, cfg.Notifications.IconURL, func() bool { return hasVIP(cfg.StaleAlert.VIP) })
	if err != nil {
		log.Fatal(err)
	}
	dynamicExcludes, err := loadDynamicExcludes(&keyDBInst, 5, time.Second)
	if err != nil {
		log.Fatal(err)
	}
	snapshotExcludes, err := readDynamicExcludesSnapshot(snapshotPath)
	if err != nil {
		log.Printf("dynamic excludes snapshot load failed path=%s err=%v", snapshotPath, err)
	} else if len(dynamicExcludes) == 0 && len(snapshotExcludes) > 0 {
		dynamicExcludes = snapshotExcludes
		if err := keyDBInst.SetDynExcludes(dynamicExcludes); err != nil {
			log.Printf("dynamic excludes snapshot restore failed path=%s err=%v", snapshotPath, err)
		} else {
			log.Printf("dynamic excludes restored from snapshot path=%s entries=%d", snapshotPath, len(dynamicExcludes))
		}
	}
	dynamicExcludesStore := newDynamicExcludesStore(dynamicExcludes)
	if err := dynamicExcludesStore.SnapshotToFile(snapshotPath); err != nil {
		log.Printf("dynamic excludes initial snapshot failed path=%s err=%v", snapshotPath, err)
	}
	startDynamicExcludesSnapshotter(ctx, dynamicExcludesStore, snapshotPath, defaultDynamicExcludesSnapshotInterval, metrics)
	startDynamicExcludesRefresher(ctx, dynamicExcludesStore, &keyDBInst, 5*time.Second, metrics)

	webServer := newWebServer(cfg.Web.ListenAddress, dynamicExcludesStore, &keyDBInst, cfg.Web.Tokens, cfg.Web.APITokens, metrics)
	webErrors := startWeb(webServer)
	go func() {
		if err := <-webErrors; err != nil {
			metrics.ready.Store(false)
			log.Printf("web server stopped address=%s err=%v", cfg.Web.ListenAddress, err)
		}
	}()
	processExcludes := compileProcessExcludes(cfg.Processes.Excludes)
	if len(processExcludes) > 0 {
		log.Printf("process excludes active: %d pattern(s)", len(processExcludes))
	}

	if cfg.DecisionService.Enabled {
		log.Printf("decision service enabled: url=%s", cfg.DecisionService.URL)
	}
	engine := &alertEngine{
		monitors: monitors, dynamicExcludes: dynamicExcludesStore, processExcludes: processExcludes,
		notifier: notifier, iconURL: cfg.Notifications.IconURL, decisionCfg: cfg.DecisionService,
		dedupCfg: cfg.AlertDedup, deduper: deduper, decisionCache: newDecisionCache(),
		incidents: incidents, metrics: metrics,
	}
	incidents.metrics = metrics
	incidents.Start(ctx)
	workerCount, queueSize := cfg.Pipeline.values()
	alertJobs := make(chan string, queueSize)
	go sampleOutboxDepth(ctx, &keyDBInst, metrics)
	var workerWG sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for line := range alertJobs {
				metrics.queueDepth.Store(int64(len(alertJobs)))
				metrics.jobsStarted.Add(1)
				engine.checkLine(line)
				metrics.jobsCompleted.Add(1)
			}
		}()
	}
	log.Printf("alert pipeline active: workers=%d queue_size=%d", workerCount, queueSize)

	var tailWG sync.WaitGroup
	for _, monFile := range cfg.MonFiles {
		monFile := monFile
		go watchFileActivity(ctx, monFile, cfg.StaleAlert, notifier, cfg.Notifications.IconURL, metrics)
		tailWG.Add(1)
		go func() {
			defer tailWG.Done()
			var nextOffset int64
			offsetInitialized := false
			for {
				if ctx.Err() != nil {
					return
				}
				log.Println("Monitoring:", monFile)
				fileInfo, statErr := os.Stat(monFile)
				if statErr != nil {
					log.Printf("tail stat failed path=%s err=%v; retrying", monFile, statErr)
					if !sleepContext(ctx, 5*time.Second) {
						return
					}
					continue
				}
				if !offsetInitialized {
					nextOffset = fileInfo.Size()
					offsetInitialized = true
				} else if nextOffset > fileInfo.Size() {
					nextOffset = 0
				}
				seekInfo := tail.SeekInfo{Offset: nextOffset, Whence: 0}
				t, tailErr := tail.TailFile(monFile, tail.Config{Follow: true, CompleteLines: true, ReOpen: true, Location: &seekInfo})
				if tailErr != nil {
					log.Printf("tail start failed path=%s err=%v; retrying", monFile, tailErr)
					if !sleepContext(ctx, 5*time.Second) {
						return
					}
					continue
				}
				for {
					select {
					case <-ctx.Done():
						_ = t.Stop()
						return
					case line, ok := <-t.Lines:
						if !ok {
							goto tailStopped
						}
						if line.Err != nil {
							log.Printf("tail line error path=%s err=%v", monFile, line.Err)
							continue
						}
						metrics.linesRead.Add(1)
						metrics.lastLineUnix.Store(time.Now().Unix())
						select {
						case <-ctx.Done():
							_ = t.Stop()
							return
						case alertJobs <- line.Text:
							metrics.queueDepth.Store(int64(len(alertJobs)))
						default:
							metrics.queueSaturations.Add(1)
							log.Printf("alert pipeline queue saturated path=%s; applying backpressure", monFile)
							select {
							case <-ctx.Done():
								_ = t.Stop()
								return
							case alertJobs <- line.Text:
								metrics.queueDepth.Store(int64(len(alertJobs)))
							}
						}
					}
				}
			tailStopped:
				if offset, tellErr := t.Tell(); tellErr != nil {
					log.Printf("tail offset unavailable path=%s err=%v", monFile, tellErr)
				} else {
					nextOffset = offset
				}
				msg := fmt.Sprintf(":warning: Log tail stopped for `%s`; retrying in 5 seconds", monFile)
				metrics.tailRestarts.Add(1)
				log.Println(msg)
				alertLog.Println(msg)
				card := tintwireCard{Version: 1, Title: "Log tail stopped", Summary: "Log monitoring stopped unexpectedly and will be restarted", Severity: "critical", Source: "clattermark", Fields: []tintwireField{{Label: "Path", Value: monFile}}}
				if notifyErr := notifier.Send(card, "clattermark", "", msg, cfg.Notifications.IconURL); notifyErr != nil {
					metrics.notificationFailures.Add(1)
					log.Printf("tail failure notification path=%s err=%v", monFile, notifyErr)
				}
				if !sleepContext(ctx, 5*time.Second) {
					return
				}
			}
		}()
	}
	metrics.ready.Store(true)
	log.Println("clattermark ready")
	<-ctx.Done()
	metrics.shuttingDown.Store(true)
	metrics.ready.Store(false)
	log.Println("shutdown requested; stopping ingestion")
	tailWG.Wait()
	close(alertJobs)
	drained := make(chan struct{})
	go func() { workerWG.Wait(); close(drained) }()
	didDrain := false
	drainTimeout := 30 * time.Second
	if cfg.DecisionService.Enabled && decisionTimeout(cfg.DecisionService)+5*time.Second > drainTimeout {
		drainTimeout = decisionTimeout(cfg.DecisionService) + 5*time.Second
	}
	select {
	case <-drained:
		didDrain = true
		log.Println("alert pipeline drained")
	case <-time.After(drainTimeout):
		log.Println("alert pipeline drain timed out")
	}
	if err := dynamicExcludesStore.SnapshotToFile(snapshotPath); err != nil {
		log.Printf("dynamic excludes final snapshot failed: %v", err)
	}
	if err := shutdownWeb(webServer, 5*time.Second); err != nil {
		log.Printf("web server shutdown: %v", err)
	}
	if didDrain {
		_ = keyDBInst.Close()
	}
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func sampleOutboxDepth(ctx context.Context, store *keydb.Keydb, metrics *telemetry) {
	if store == nil || metrics == nil {
		return
	}
	sample := func() {
		incidentDepth, incidentErr := store.QueueLength(incidentRecoveryOutboxKey)
		if incidentErr != nil {
			metrics.keyDBFailures.Add(1)
			return
		}
		metrics.incidentOutboxDepth.Store(incidentDepth)
	}
	sample()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sample()
		}
	}
}
