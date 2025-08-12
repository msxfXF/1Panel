package service

import (
	"encoding/json"
	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/model"
	"github.com/1Panel-dev/1Panel/agent/app/repo"
	"github.com/1Panel-dev/1Panel/agent/constant"
	"github.com/1Panel-dev/1Panel/agent/global"
	alertUtil "github.com/1Panel-dev/1Panel/agent/utils/alert"
	"github.com/1Panel-dev/1Panel/agent/utils/common"
	versionUtil "github.com/1Panel-dev/1Panel/agent/utils/version"
	"github.com/1Panel-dev/1Panel/agent/utils/xpack"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

type AlertTaskHelper struct {
	DiskIO chan []disk.IOCountersStat
	NetIO  chan []net.IOCountersStat
}

type IAlertTaskHelper interface {
	StopTask()
	StartTask()
	ResetTask()
	InitTask(alertType string)
}

var cpuLoad1, cpuLoad5, cpuLoad15 []float64
var memoryLoad1, memoryLoad5, memoryLoad15 []float64

const ResourceAlertInterval = 30

var baseTypes = map[string]bool{"ssl": true, "siteEndTime": true, "panelPwdEndTime": true, "panelUpdate": true}
var resourceTypes = map[string]bool{"cpu": true, "memory": true, "disk": true, "load": true, "panelLogin": true, "sshLogin": true, "nodeException": true, "licenseException": true}

func NewIAlertTaskHelper() IAlertTaskHelper {
	return &AlertTaskHelper{}
}
func (m *AlertTaskHelper) StartTask() {
	baseAlert, resourceAlert := handleTask()
	if len(baseAlert) == 0 && len(resourceAlert) == 0 {
		return
	}
	handleBaseAlerts(baseAlert)
	handleResourceAlerts(resourceAlert)
}

func (m *AlertTaskHelper) StopTask() {
	stopBaseJob()
	stopResourceJob()
}

func (m *AlertTaskHelper) ResetTask() {
	m.StopTask()
	m.StartTask()
}

func (m *AlertTaskHelper) InitTask(alertType string) {
	if alertType == "cpu" {
		cpuLoad1 = []float64{}
		cpuLoad5 = []float64{}
		cpuLoad15 = []float64{}
	}
	if alertType == "memory" {
		memoryLoad1 = []float64{}
		memoryLoad5 = []float64{}
		memoryLoad15 = []float64{}
	}
	if baseTypes[alertType] {
		stopBaseJob()
	} else if resourceTypes[alertType] {
		stopResourceJob()
	}
	m.StartTask()
}

func resourceTask(resourceAlert []dto.AlertDTO) {
	minute := time.Now().Minute()
	for _, alert := range resourceAlert {
		if !alertUtil.CheckSendTimeRange(alert.Type) {
			continue
		}
		execute := minute%5 == 0
		switch alert.Type {
		case "cpu":
			loadCPUUsage(alert)
		case "memory":
			loadMemUsage(alert)
		case "load":
			loadLoadInfo(alert)
		case "disk":
			loadDiskUsage(alert)
		case "panelLogin":
			loadPanelLogin(alert)
		case "sshLogin":
			loadSSHLogin(alert)
		case "nodeException":
			if execute && global.IsMaster {
				loadNodeException(alert)
			}
		case "licenseException":
			if execute && global.IsMaster {
				loadLicenseException(alert)
			}
		default:
		}
	}
}

func baseTask(baseAlert []dto.AlertDTO) {
	for _, alert := range baseAlert {
		if !alertUtil.CheckSendTimeRange(alert.Type) {
			continue
		}
		switch alert.Type {
		case "ssl":
			loadSSLInfo(alert)
		case "siteEndTime":
			loadWebsiteInfo(alert)
		case "panelPwdEndTime":
			if global.IsMaster {
				loadPanelPwd(alert)
			}
		case "panelUpdate":
			if global.IsMaster {
				loadPanelUpdate(alert)
			}
		default:
		}
	}
}

func handleTask() (baseAlert []dto.AlertDTO, resourceAlert []dto.AlertDTO) {
	alertList, _ := NewIAlertService().GetAlerts()
	baseAlert, resourceAlert = classifyAlerts(alertList)
	return baseAlert, resourceAlert
}

func classifyAlerts(alertList []dto.AlertDTO) (baseAlert, resourceAlert []dto.AlertDTO) {
	for _, alert := range alertList {
		if baseTypes[alert.Type] {
			baseAlert = append(baseAlert, alert)
		} else if resourceTypes[alert.Type] {
			resourceAlert = append(resourceAlert, alert)
		}
	}
	return
}

func handleBaseAlerts(baseAlert []dto.AlertDTO) {
	if len(baseAlert) > 0 {
		if global.AlertBaseJobID == 0 {
			baseTask(baseAlert)
			jobID, err := global.Cron.AddFunc("*/30 * * * *", func() {
				baseTask(baseAlert)
			})
			if err != nil {
				global.LOG.Errorf("alert base job start failed: %v", err)
				return
			}
			global.AlertBaseJobID = jobID
			global.LOG.Info("start alert base job")
		}
	} else {
		stopBaseJob()
	}
}

func handleResourceAlerts(resourceAlert []dto.AlertDTO) {
	if len(resourceAlert) > 0 {
		if global.AlertResourceJobID == 0 {
			jobID, err := global.Cron.AddFunc("*/1 * * * *", func() {
				resourceTask(resourceAlert)
			})
			if err != nil {
				global.LOG.Errorf("alert resource job start failed: %v", err)
				return
			}
			global.AlertResourceJobID = jobID
			global.LOG.Info("start alert resource job")
		}
	} else {
		stopResourceJob()
	}
}

func stopBaseJob() {
	if global.AlertBaseJobID != 0 {
		global.Cron.Remove(global.AlertBaseJobID)
		global.AlertBaseJobID = 0
		global.LOG.Info("stop alert base job")
	}
}

func stopResourceJob() {
	if global.AlertResourceJobID != 0 {
		global.Cron.Remove(global.AlertResourceJobID)
		global.AlertResourceJobID = 0
		global.LOG.Info("stop alert resource job")
	}
}

func loadSSLInfo(alert dto.AlertDTO) {
	var opts []repo.DBOption
	if alert.Project != "all" {
		itemID, _ := strconv.Atoi(alert.Project)
		opts = append(opts, repo.WithByID(uint(itemID)))
	}

	sslList, _ := repo.NewISSLRepo().List(opts...)
	currentDate := time.Now()
	daysDifferenceMap := make(map[int][]string)
	projectMap := make(map[uint][]time.Time)
	for _, ssl := range sslList {
		daysDifference := int(ssl.ExpireDate.Sub(currentDate).Hours() / 24)
		if daysDifference > 0 && int(alert.Cycle) >= daysDifference {
			daysDifferenceMap[daysDifference] = append(daysDifferenceMap[daysDifference], ssl.PrimaryDomain)
			projectMap[ssl.ID] = append(projectMap[ssl.ID], ssl.ExpireDate)
		}
	}
	projectJSON := serializeAndSortProjects(projectMap)
	if projectJSON == "" {
		return
	}
	if len(daysDifferenceMap) > 0 {
		for daysDifference, ssl := range daysDifferenceMap {
			primaryDomain := strings.Join(ssl, ",")
			params := createAlertBaseParams(strconv.Itoa(len(ssl)), strconv.Itoa(daysDifference))
			methods := strings.Split(alert.Method, ",")
			for _, m := range methods {
				m = strings.TrimSpace(m)
				switch m {
				case constant.SMS:
					todayCount, totalCount, err := alertRepo.LoadTaskCount(alert.Type, projectJSON, constant.SMS)
					if err != nil || todayCount >= 1 || alert.SendCount <= totalCount {
						continue
					}
					create := dto.AlertLogCreate{
						Status:  constant.AlertSuccess,
						Count:   totalCount + 1,
						AlertId: alert.ID,
						Type:    alert.Type,
					}
					if !alertUtil.CheckSMSSendLimit(constant.SMS) {
						continue
					}
					_ = xpack.CreateSMSAlertLog(alert.Type, alert, create, primaryDomain, params, constant.SMS)
					alertUtil.CreateNewAlertTask(alert.Project, alert.Type, projectJSON, constant.SMS)
					global.LOG.Info("SSL alert sms push successful")
				case constant.Email:
					todayCount, totalCount, err := alertRepo.LoadTaskCount(alert.Type, projectJSON, constant.Email)
					if err != nil || todayCount >= 1 || alert.SendCount <= totalCount {
						continue
					}
					create := dto.AlertLogCreate{
						Status:  constant.AlertSuccess,
						Count:   totalCount + 1,
						AlertId: alert.ID,
						Type:    alert.Type,
					}
					alertDetail := alertUtil.ProcessAlertDetail(alert, primaryDomain, params, constant.Email)
					alertRule := alertUtil.ProcessAlertRule(alert)
					create.AlertRule = alertRule
					create.AlertDetail = alertDetail
					transport := xpack.LoadRequestTransport()
					_ = alertUtil.CreateEmailAlertLog(create, alert, params, transport)
					alertUtil.CreateNewAlertTask(alert.Project, alert.Type, projectJSON, constant.Email)
					global.LOG.Info("SSL alert email push successful")
				default:
				}
			}
		}
	}
}

func loadWebsiteInfo(alert dto.AlertDTO) {
	var opts []repo.DBOption
	if alert.Project != "all" {
		itemID, _ := strconv.Atoi(alert.Project)
		opts = append(opts, repo.WithByID(uint(itemID)))
	}

	websiteList, _ := websiteRepo.List(opts...)
	currentDate := time.Now()
	daysDifferenceMap := make(map[int][]string)
	projectMap := make(map[uint][]time.Time)
	for _, website := range websiteList {
		daysDifference := int(website.ExpireDate.Sub(currentDate).Hours() / 24)
		if daysDifference > 0 && int(alert.Cycle) >= daysDifference {
			daysDifferenceMap[daysDifference] = append(daysDifferenceMap[daysDifference], website.PrimaryDomain)
			projectMap[website.ID] = append(projectMap[website.ID], website.ExpireDate)
		}
	}
	projectJSON := serializeAndSortProjects(projectMap)
	if projectJSON == "" {
		return
	}
	if len(daysDifferenceMap) > 0 {
		methods := strings.Split(alert.Method, ",")
		for daysDifference, websites := range daysDifferenceMap {
			primaryDomain := strings.Join(websites, ",")
			params := createAlertBaseParams(strconv.Itoa(len(websites)), strconv.Itoa(daysDifference))
			for _, m := range methods {
				m = strings.TrimSpace(m)
				switch m {
				case constant.SMS:
					if !alertUtil.CheckSMSSendLimit(constant.SMS) {
						continue
					}
					todayCount, totalCount, err := alertRepo.LoadTaskCount(alert.Type, projectJSON, constant.SMS)
					if err != nil || todayCount >= 1 || alert.SendCount <= totalCount {
						continue
					}
					create := dto.AlertLogCreate{
						Status:  constant.AlertSuccess,
						Count:   totalCount + 1,
						AlertId: alert.ID,
						Type:    alert.Type,
					}
					_ = xpack.CreateSMSAlertLog(alert.Type, alert, create, primaryDomain, params, constant.SMS)
					alertUtil.CreateNewAlertTask(alert.Project, alert.Type, projectJSON, constant.SMS)
					global.LOG.Info("website expiration alert sms push successful")
				case constant.Email:
					todayCount, totalCount, err := alertRepo.LoadTaskCount(alert.Type, projectJSON, constant.Email)
					if err != nil || todayCount >= 1 || alert.SendCount <= totalCount {
						continue
					}
					create := dto.AlertLogCreate{
						Status:  constant.AlertSuccess,
						Count:   totalCount + 1,
						AlertId: alert.ID,
						Type:    alert.Type,
					}
					alertDetail := alertUtil.ProcessAlertDetail(alert, primaryDomain, params, constant.Email)
					alertRule := alertUtil.ProcessAlertRule(alert)
					create.AlertDetail = alertDetail
					create.AlertRule = alertRule
					transport := xpack.LoadRequestTransport()
					_ = alertUtil.CreateEmailAlertLog(create, alert, params, transport)
					alertUtil.CreateNewAlertTask(alert.Project, alert.Type, projectJSON, constant.Email)
					global.LOG.Info("website expiration alert email push successful")
				default:
				}
			}
		}
	}
}

func loadPanelPwd(alert dto.AlertDTO) {
	// only master alert
	var expirationDays model.Setting
	if err := global.CoreDB.Model(&model.Setting{}).Where("key = ?", "ExpirationDays").First(&expirationDays).Error; err != nil {
		global.LOG.Errorf("load %s from db setting failed, err: %v", "ExpirationDays", err)
		return
	}
	if expirationDays.Value == "0" {
		global.LOG.Info("panel password expiration setting not enabled, skip")
		return
	}
	var expirationTime model.Setting
	if err := global.CoreDB.Model(&model.Setting{}).Where("key = ?", "ExpirationTime").First(&expirationTime).Error; err != nil {
		global.LOG.Errorf("load %s from db setting failed, err: %v", "ExpirationTime", err)
		return
	}

	defaultDate, _ := time.Parse(constant.DateTimeLayout, expirationTime.Value)
	daysDifference := calculateDaysDifference(defaultDate)
	if daysDifference >= 0 && int(alert.Cycle) >= daysDifference {
		params := createAlertPwdParams(strconv.Itoa(daysDifference))
		methods := strings.Split(alert.Method, ",")
		for _, m := range methods {
			m = strings.TrimSpace(m)
			switch m {
			case constant.SMS:
				if !alertUtil.CheckSMSSendLimit(constant.SMS) {
					continue
				}
				todayCount, totalCount, err := alertRepo.LoadTaskCount(alert.Type, expirationTime.Value, constant.SMS)
				if err != nil || todayCount >= 1 || alert.SendCount <= totalCount {
					continue
				}
				create := dto.AlertLogCreate{
					Count:   totalCount + 1,
					AlertId: alert.ID,
					Type:    alert.Type,
				}
				_ = xpack.CreateSMSAlertLog(alert.Type, alert, create, strconv.Itoa(daysDifference), params, constant.SMS)
				alertUtil.CreateNewAlertTask(expirationTime.Value, alert.Type, expirationTime.Value, constant.SMS)
				global.LOG.Info("panel password expiration alert sms push successful")
			case constant.Email:
				todayCount, totalCount, err := alertRepo.LoadTaskCount(alert.Type, expirationTime.Value, constant.Email)
				if err != nil || todayCount >= 1 || alert.SendCount <= totalCount {
					continue
				}
				create := dto.AlertLogCreate{
					Count:   totalCount + 1,
					AlertId: alert.ID,
					Type:    alert.Type,
				}
				alertDetail := alertUtil.ProcessAlertDetail(alert, strconv.Itoa(daysDifference), params, constant.Email)
				alertRule := alertUtil.ProcessAlertRule(alert)
				create.AlertRule = alertRule
				create.AlertDetail = alertDetail
				transport := xpack.LoadRequestTransport()
				_ = alertUtil.CreateEmailAlertLog(create, alert, params, transport)
				alertUtil.CreateNewAlertTask(expirationTime.Value, alert.Type, expirationTime.Value, constant.Email)
				global.LOG.Info("panel password expiration alert email push successful")
			default:
			}
		}
	}
}

func loadPanelUpdate(alert dto.AlertDTO) {
	// only master alert
	info, err := versionUtil.GetUpgradeVersionInfo()
	if err != nil {
		global.LOG.Errorf("error getting version, err: %s", err)
		return
	}

	// 获取版本信息
	var version string
	// 检查哪个版本字段不为空，并赋值
	if info.NewVersion != "" {
		version = info.NewVersion
	} else if info.TestVersion != "" {
		version = info.TestVersion
	} else if info.LatestVersion != "" {
		version = info.LatestVersion
	}
	if version == "" {
		return
	}

	var params []dto.Param
	methods := strings.Split(alert.Method, ",")
	for _, m := range methods {
		m = strings.TrimSpace(m)
		switch m {
		case constant.SMS:
			if !alertUtil.CheckSMSSendLimit(constant.SMS) {
				continue
			}
			todayCount, totalCount, err := alertRepo.LoadTaskCount(alert.Type, version, constant.SMS)
			if err != nil || todayCount >= 1 || alert.SendCount <= totalCount {
				continue
			}
			var create = dto.AlertLogCreate{
				Type:    alert.Type,
				AlertId: alert.ID,
				Count:   totalCount + 1,
			}
			_ = xpack.CreateSMSAlertLog(alert.Type, alert, create, version, params, constant.SMS)
			alertUtil.CreateNewAlertTask(version, alert.Type, version, constant.SMS)
			global.LOG.Info("panel update alert sms push successful")
		case constant.Email:
			todayCount, totalCount, err := alertRepo.LoadTaskCount(alert.Type, version, constant.Email)
			if err != nil || todayCount >= 1 || alert.SendCount <= totalCount {
				continue
			}
			var create = dto.AlertLogCreate{
				Type:    alert.Type,
				AlertId: alert.ID,
				Count:   totalCount + 1,
			}
			alertDetail := alertUtil.ProcessAlertDetail(alert, version, params, constant.Email)
			alertRule := alertUtil.ProcessAlertRule(alert)
			create.AlertRule = alertRule
			create.AlertDetail = alertDetail
			transport := xpack.LoadRequestTransport()
			_ = alertUtil.CreateEmailAlertLog(create, alert, params, transport)
			alertUtil.CreateNewAlertTask(version, alert.Type, version, constant.Email)
			global.LOG.Info("panel update alert email push successful")
		default:
		}
	}
}

// 获取 CPU 使用率数据并发送到通道
func loadCPUUsage(alert dto.AlertDTO) {
	percent, err := cpu.Percent(3*time.Second, false)
	if err != nil {
		global.LOG.Errorf("error getting cpu usage, err: %v", err)
		return
	}

	if len(percent) > 0 {
		var cpuLoad *[]float64
		var threshold int

		switch alert.Cycle {
		case 1:
			cpuLoad = &cpuLoad1
			threshold = 1
		case 5:
			cpuLoad = &cpuLoad5
			threshold = 5
		case 15:
			cpuLoad = &cpuLoad15
			threshold = 15
		default:
			return
		}

		if checkAndSendAlert(alert, percent[0], cpuLoad, threshold) {
			global.LOG.Info("cpu alert push successful")
		}
	}

}

// 获取内存使用情况数据并发送到通道
func loadMemUsage(alert dto.AlertDTO) {

	memStat, err := mem.VirtualMemory()
	if err != nil {
		global.LOG.Errorf("error getting memory usage, err: %v", err)
		return
	}

	percent := memStat.UsedPercent
	var memoryLoad *[]float64
	var threshold int

	switch alert.Cycle {
	case 1:
		memoryLoad = &memoryLoad1
		threshold = 1
	case 5:
		memoryLoad = &memoryLoad5
		threshold = 5
	case 15:
		memoryLoad = &memoryLoad15
		threshold = 15
	default:
		return
	}
	if checkAndSendAlert(alert, percent, memoryLoad, threshold) {
		global.LOG.Info("memory alert push successful")
	}
}

// 获取系统负载数据并发送到通道
func loadLoadInfo(alert dto.AlertDTO) {
	avgStat, err := load.Avg()
	if err != nil {
		global.LOG.Errorf("error getting load usage, err: %v", err)
		return
	}
	var loadValue float64
	CPUTotal, _ := cpu.Counts(true)
	switch alert.Cycle {
	case 1:
		loadValue = avgStat.Load1 / (float64(CPUTotal*2) * 0.75) * 100
	case 5:
		loadValue = avgStat.Load5 / (float64(CPUTotal*2) * 0.75) * 100
	case 15:
		loadValue = avgStat.Load15 / (float64(CPUTotal*2) * 0.75) * 100
	default:
		return
	}
	newDate, err := alertRepo.GetTaskLog(alert.Type, alert.ID)
	if err != nil {
		global.LOG.Errorf("task log record not found, err: %v", err)
	}
	if newDate.IsZero() || calculateMinutesDifference(newDate) > ResourceAlertInterval {
		if loadValue >= float64(alert.Count) {
			global.LOG.Infof("%d minute load: %f,detail: %v", alert.Cycle, loadValue, avgStat)
			createAndLogAlert(alert, loadValue)
			global.LOG.Info("load alert task push successful")
		}
	}
}

// 内存/cpu检查是否需要发送告警并处理相关逻辑
func checkAndSendAlert(alert dto.AlertDTO, currentUsage float64, usageLoad *[]float64, threshold int) bool {
	newDate, err := alertRepo.GetTaskLog(alert.Type, alert.ID)
	if err != nil {
		global.LOG.Errorf("record not found, err: %v", err)
		return false
	}

	*usageLoad = append(*usageLoad, currentUsage)

	if len(*usageLoad) > threshold {
		*usageLoad = (*usageLoad)[1:]
	}

	if newDate.IsZero() || calculateMinutesDifference(newDate) > ResourceAlertInterval {
		if len(*usageLoad) == threshold {
			avgUsage := average(*usageLoad)
			if avgUsage >= float64(alert.Count) {
				global.LOG.Infof("%d minute %s: %f , usage: %v", threshold, alert.Type, avgUsage, usageLoad)
				createAndLogAlert(alert, avgUsage)
				return true
			}
		}
	}
	return false
}

// 检查是否超过今日发送次数限制
func canSendAlertToday(alertType, quotaType string, sendCount uint, method string) (uint, bool) {
	todayCount, _, err := alertRepo.LoadTaskCount(alertType, quotaType, method)
	if err != nil {
		global.LOG.Errorf("error getting task info, err: %v", err)
		return todayCount, false
	}
	if todayCount >= sendCount {
		return todayCount, false
	}

	return todayCount, true
}

// 创建告警日志和详情
func createAndLogAlert(alert dto.AlertDTO, avgUsage float64) {
	avgUsagePercent := common.FormatPercent(avgUsage)
	params := createAlertAvgParams(strconv.Itoa(int(alert.Cycle)), getModule(alert.Type), avgUsagePercent)
	methods := strings.Split(alert.Method, ",")
	for _, m := range methods {
		m = strings.TrimSpace(m)
		switch m {
		case constant.SMS:
			if !alertUtil.CheckSMSSendLimit(constant.SMS) {
				continue
			}
			todayCount, isValid := canSendAlertToday(alert.Type, strconv.Itoa(int(alert.Cycle)), alert.SendCount, constant.SMS)
			if !isValid {
				continue
			}
			create := dto.AlertLogCreate{
				Status:  constant.AlertSuccess,
				Count:   todayCount + 1,
				AlertId: alert.ID,
				Type:    alert.Type,
			}
			_ = xpack.CreateSMSAlertLog(alert.Type, alert, create, avgUsagePercent, params, constant.SMS)
			alertUtil.CreateNewAlertTask(avgUsagePercent, alert.Type, strconv.Itoa(int(alert.Cycle)), constant.SMS)
		case constant.Email:
			todayCount, isValid := canSendAlertToday(alert.Type, strconv.Itoa(int(alert.Cycle)), alert.SendCount, constant.Email)
			if !isValid {
				continue
			}
			create := dto.AlertLogCreate{
				Status:  constant.AlertSuccess,
				Count:   todayCount + 1,
				AlertId: alert.ID,
				Type:    alert.Type,
			}
			alertDetail := alertUtil.ProcessAlertDetail(alert, avgUsagePercent, params, constant.Email)
			alertRule := alertUtil.ProcessAlertRule(alert)
			create.AlertRule = alertRule
			create.AlertDetail = alertDetail
			transport := xpack.LoadRequestTransport()
			_ = alertUtil.CreateEmailAlertLog(create, alert, params, transport)
			alertUtil.CreateNewAlertTask(avgUsagePercent, alert.Type, strconv.Itoa(int(alert.Cycle)), constant.Email)
		default:
		}
	}
}

func getModule(alertType string) string {
	var module string
	switch alertType {
	case "cpu":
		module = " CPU "
	case "memory":
		module = "内存"
	case "load":
		module = "负载"
	default:
	}
	return module
}

func loadDiskUsage(alert dto.AlertDTO) {
	newDate, err := alertRepo.GetTaskLog(alert.Type, alert.ID)
	if err != nil {
		global.LOG.Errorf("record not found, err: %v", err)
	}

	if newDate.IsZero() || calculateMinutesDifference(newDate) > ResourceAlertInterval {
		if strings.Contains(alert.Project, "all") {
			err = processAllDisks(alert)
		} else {
			err = processSingleDisk(alert)
		}
		if err != nil {
			global.LOG.Errorf("error processing disk usage, err: %v", err)
		}
	}
}

func processAllDisks(alert dto.AlertDTO) error {
	diskList, err := NewIAlertService().GetDisks()
	if err != nil {
		global.LOG.Errorf("error getting disk list, err: %v", err)
		return err
	}

	var flag bool
	for _, item := range diskList {
		if success, err := checkAndCreateDiskAlert(alert, item.Path); err == nil && success {
			flag = true
		}
	}
	if flag {
		global.LOG.Info("all disk alert push successful")
	}
	return nil
}

func processSingleDisk(alert dto.AlertDTO) error {
	success, err := checkAndCreateDiskAlert(alert, alert.Project)
	if err != nil {
		return err
	}
	if success {
		global.LOG.Info("disk alert push successful")
	}
	return nil
}

func checkAndCreateDiskAlert(alert dto.AlertDTO, path string) (bool, error) {
	usageStat, err := disk.Usage(path)
	if err != nil {
		global.LOG.Errorf("error getting disk usage for %s, err: %v", path, err)
		return false, err
	}

	usedTotal, usedStr := calculateUsedTotal(alert.Cycle, usageStat)
	commonTotal := float64(alert.Count)
	if alert.Cycle == 1 {
		commonTotal *= 1024 * 1024 * 1024
	}
	if usedTotal < commonTotal {
		return false, nil
	}
	global.LOG.Infof("disk「 %s 」usage: %s", path, usedStr)
	params := createAlertDiskParams(path, usedStr)
	methods := strings.Split(alert.Method, ",")
	for _, m := range methods {
		m = strings.TrimSpace(m)
		switch m {
		case constant.SMS:
			if !alertUtil.CheckSMSSendLimit(constant.SMS) {
				continue
			}
			todayCount, isValid := canSendAlertToday(alert.Type, alert.Project, alert.SendCount, constant.SMS)
			if !isValid {
				continue
			}
			create := dto.AlertLogCreate{
				Status:  constant.AlertSuccess,
				Count:   todayCount + 1,
				AlertId: alert.ID,
				Type:    alert.Type,
			}
			_ = xpack.CreateSMSAlertLog(alert.Type, alert, create, path, params, constant.SMS)
			alertUtil.CreateNewAlertTask(strconv.Itoa(int(alert.Cycle)), alert.Type, alert.Project, constant.SMS)
		case constant.Email:
			todayCount, isValid := canSendAlertToday(alert.Type, alert.Project, alert.SendCount, constant.Email)
			if !isValid {
				continue
			}
			create := dto.AlertLogCreate{
				Status:  constant.AlertSuccess,
				Count:   todayCount + 1,
				AlertId: alert.ID,
				Type:    alert.Type,
			}
			alertDetail := alertUtil.ProcessAlertDetail(alert, path, params, constant.Email)
			alertRule := alertUtil.ProcessAlertRule(alert)
			create.AlertRule = alertRule
			create.AlertDetail = alertDetail
			transport := xpack.LoadRequestTransport()
			_ = alertUtil.CreateEmailAlertLog(create, alert, params, transport)
			alertUtil.CreateNewAlertTask(strconv.Itoa(int(alert.Cycle)), alert.Type, alert.Project, constant.Email)
		default:
		}
	}

	return true, nil
}

func calculateUsedTotal(cycle uint, usageStat *disk.UsageStat) (float64, string) {
	if cycle == 1 {
		return float64(usageStat.Used), common.FormatBytes(usageStat.Used)
	}
	return usageStat.UsedPercent, common.FormatPercent(usageStat.UsedPercent)
}

func calculateDaysDifference(expirationTime time.Time) int {
	currentDate := time.Now()
	formattedTime := currentDate.Format(constant.DateTimeLayout)
	parsedTime, _ := time.Parse(constant.DateTimeLayout, formattedTime)
	timeGap := expirationTime.Sub(parsedTime).Milliseconds()
	if timeGap < 0 {
		return -1
	}
	daysDifference := int(math.Floor(float64(timeGap) / (3600 * 1000 * 24)))
	return daysDifference
}

func calculateMinutesDifference(newDate time.Time) int {
	now := time.Now()
	if newDate.After(now) {
		return -1
	}
	minutesDifference := int(now.Sub(newDate).Minutes())
	return minutesDifference
}

func average(arr []float64) float64 {
	total := 0.0
	for _, v := range arr {
		total += v
	}
	return total / float64(len(arr))
}

func createAlertBaseParams(project, cycle string) []dto.Param {
	return []dto.Param{
		{
			Index: "1",
			Key:   "project",
			Value: project,
		},
		{
			Index: "2",
			Key:   "cycle",
			Value: cycle,
		},
	}
}

func createAlertPwdParams(cycle string) []dto.Param {
	return []dto.Param{
		{
			Index: "1",
			Key:   "cycle",
			Value: cycle,
		},
	}
}

func createAlertAvgParams(cycle, module, count string) []dto.Param {
	return []dto.Param{
		{
			Index: "1",
			Key:   "cycle",
			Value: cycle,
		},
		{
			Index: "2",
			Key:   "module",
			Value: module,
		},
		{
			Index: "3",
			Key:   "count",
			Value: count,
		},
	}
}

func createAlertDiskParams(project, count string) []dto.Param {
	return []dto.Param{
		{
			Index: "1",
			Key:   "project",
			Value: project,
		},
		{
			Index: "2",
			Key:   "count",
			Value: count,
		},
	}
}

func serializeAndSortProjects(projectMap map[uint][]time.Time) string {
	keys := make([]int, 0, len(projectMap))
	for k := range projectMap {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	projectJSON, err := json.Marshal(projectMap)
	if err != nil {
		global.LOG.Errorf("Failed to serialize projectMap: %v", err)
		return ""
	}

	return string(projectJSON)
}

func loadNodeException(alert dto.AlertDTO) {
	// only master alert
	failCount, err := xpack.GetNodeErrorAlert()
	if err != nil {
		global.LOG.Errorf("error getting node, err: %s", err)
		return
	}
	if failCount > 0 {
		quotaType := "node-error"
		params := []dto.Param{
			{
				Index: "1",
				Key:   "cycle",
				Value: strconv.Itoa(int(failCount)),
			},
		}
		methods := strings.Split(alert.Method, ",")
		newDate, err := alertRepo.GetTaskLog(alert.Type, alert.ID)
		if err != nil {
			global.LOG.Errorf("task log record not found, err: %v", err)
		}
		if newDate.IsZero() || calculateMinutesDifference(newDate) > ResourceAlertInterval {
			for _, m := range methods {
				m = strings.TrimSpace(m)
				switch m {
				case constant.SMS:
					if !alertUtil.CheckSMSSendLimit(constant.SMS) {
						continue
					}
					todayCount, isValid := canSendAlertToday(alert.Type, quotaType, alert.SendCount, constant.SMS)
					if !isValid {
						continue
					}
					var create = dto.AlertLogCreate{
						Type:    alert.Type,
						AlertId: alert.ID,
						Count:   todayCount + 1,
					}
					_ = xpack.CreateSMSAlertLog(alert.Type, alert, create, quotaType, params, constant.SMS)
					alertUtil.CreateNewAlertTask(strconv.Itoa(int(failCount)), alert.Type, quotaType, constant.SMS)
					global.LOG.Info("node exception alert sms push successful")
				case constant.Email:
					todayCount, isValid := canSendAlertToday(alert.Type, quotaType, alert.SendCount, constant.Email)
					if !isValid {
						continue
					}
					var create = dto.AlertLogCreate{
						Type:    alert.Type,
						AlertId: alert.ID,
						Count:   todayCount + 1,
					}
					alertDetail := alertUtil.ProcessAlertDetail(alert, quotaType, params, constant.Email)
					alertRule := alertUtil.ProcessAlertRule(alert)
					create.AlertRule = alertRule
					create.AlertDetail = alertDetail
					transport := xpack.LoadRequestTransport()
					_ = alertUtil.CreateEmailAlertLog(create, alert, params, transport)
					alertUtil.CreateNewAlertTask(strconv.Itoa(int(failCount)), alert.Type, quotaType, constant.Email)
					global.LOG.Info("node exception alert email push successful")
				default:
				}
			}
		}
	}

}

func loadLicenseException(alert dto.AlertDTO) {
	// only master alert
	failCount, err := xpack.GetLicenseErrorAlert()
	if err != nil {
		global.LOG.Errorf("error getting license, err: %s", err)
		return
	}
	if failCount > 0 {
		quotaType := "license-error"
		params := []dto.Param{
			{
				Index: "1",
				Key:   "cycle",
				Value: strconv.Itoa(int(failCount)),
			},
		}
		methods := strings.Split(alert.Method, ",")
		newDate, err := alertRepo.GetTaskLog(alert.Type, alert.ID)
		if err != nil {
			global.LOG.Errorf("task log record not found, err: %v", err)
		}
		if newDate.IsZero() || calculateMinutesDifference(newDate) > ResourceAlertInterval {
			for _, m := range methods {
				m = strings.TrimSpace(m)
				switch m {
				case constant.SMS:
					if !alertUtil.CheckSMSSendLimit(constant.SMS) {
						continue
					}
					todayCount, isValid := canSendAlertToday(alert.Type, quotaType, alert.SendCount, constant.SMS)
					if !isValid {
						continue
					}
					var create = dto.AlertLogCreate{
						Type:    alert.Type,
						AlertId: alert.ID,
						Count:   todayCount + 1,
					}
					_ = xpack.CreateSMSAlertLog(alert.Type, alert, create, quotaType, params, constant.SMS)
					alertUtil.CreateNewAlertTask(strconv.Itoa(int(failCount)), alert.Type, quotaType, constant.SMS)
					global.LOG.Info("license exception alert sms push successful")
				case constant.Email:
					todayCount, isValid := canSendAlertToday(alert.Type, quotaType, alert.SendCount, constant.Email)
					if !isValid {
						continue
					}
					var create = dto.AlertLogCreate{
						Type:    alert.Type,
						AlertId: alert.ID,
						Count:   todayCount + 1,
					}
					alertDetail := alertUtil.ProcessAlertDetail(alert, quotaType, params, constant.Email)
					alertRule := alertUtil.ProcessAlertRule(alert)
					create.AlertRule = alertRule
					create.AlertDetail = alertDetail
					transport := xpack.LoadRequestTransport()
					_ = alertUtil.CreateEmailAlertLog(create, alert, params, transport)
					alertUtil.CreateNewAlertTask(strconv.Itoa(int(failCount)), alert.Type, quotaType, constant.Email)
					global.LOG.Info("license exception alert email push successful")
				default:
				}
			}
		}
	}
}

func loadPanelLogin(alert dto.AlertDTO) {
	count, isAlert, err := alertUtil.CountRecentFailedLoginLogs(alert.Cycle, alert.Count)
	alertType := alert.Type
	quota := strconv.Itoa(count)
	quotaType := strconv.Itoa(int(alert.Cycle))
	var params []dto.Param
	if err != nil {
		global.LOG.Errorf("Failed to count recent failed login logs: %v", err)
	}
	if isAlert {
		alertType = "panelLogin"
		quota = strconv.Itoa(count)
		quotaType = "panelLogin"
		params = append([]dto.Param{
			{
				Index: "1",
				Key:   "cycle",
				Value: "",
			},
			{
				Index: "2",
				Key:   "project",
				Value: "",
			},
		})
		sendAlerts(alert, alertType, quota, quotaType, params)
	}

	whitelist := strings.Split(strings.TrimSpace(alert.AdvancedParams), "\n")
	records, err := alertUtil.FindRecentSuccessLoginsNotInWhitelist(30, whitelist)
	if err != nil {
		global.LOG.Errorf("Failed to check recent failed ip login logs: %v", err)
	}
	if len(records) > 0 {
		quota = strings.Join(func() []string {
			var ips []string
			for _, r := range records {
				ips = append(ips, r.IP)
			}
			return ips
		}(), "\n")
		alertType = "panelIpLogin"
		quotaType = "panelIpLogin"
		params = append([]dto.Param{
			{
				Index: "1",
				Key:   "cycle",
				Value: "",
			},
			{
				Index: "2",
				Key:   "project",
				Value: " IP ",
			},
		})
		sendAlerts(alert, alertType, quota, quotaType, params)
	}
}

func loadSSHLogin(alert dto.AlertDTO) {
	count, isAlert, err := alertUtil.CountRecentFailedSSHLog(alert.Cycle, alert.Count)
	alertType := alert.Type
	quota := strconv.Itoa(count)
	quotaType := strconv.Itoa(int(alert.Cycle))
	var params []dto.Param
	if err != nil {
		global.LOG.Errorf("Failed to count recent failed ssh login logs: %v", err)
	}
	if isAlert {
		alertType = "sshLogin"
		quota = strconv.Itoa(count)
		quotaType = "sshLogin"
		params = append([]dto.Param{
			{
				Index: "1",
				Key:   "cycle",
				Value: " SSH ",
			},
			{
				Index: "2",
				Key:   "project",
				Value: "",
			},
		})
		sendAlerts(alert, alertType, quota, quotaType, params)
	}
	whitelist := strings.Split(strings.TrimSpace(alert.AdvancedParams), "\n")
	records, err := alertUtil.FindRecentSuccessLoginNotInWhitelist(30, whitelist)
	if err != nil {
		global.LOG.Errorf("Failed to check recent failed ip ssh login logs: %v", err)
	}
	if len(records) > 0 {
		quota = strings.Join(func() []string {
			var ips []string
			for _, r := range records {
				ips = append(ips, r)
			}
			return ips
		}(), "\n")
		alertType = "sshIpLogin"
		quotaType = "sshIpLogin"
		params = append([]dto.Param{
			{
				Index: "1",
				Key:   "cycle",
				Value: " SSH ",
			},
			{
				Index: "2",
				Key:   "project",
				Value: " IP ",
			},
		})
		sendAlerts(alert, alertType, quota, quotaType, params)
	}
	if isAlert || len(records) > 0 {
		var params []dto.Param
		methods := strings.Split(alert.Method, ",")
		alertInfo := alert
		alertInfo.Type = alertType
		newDate, err := alertRepo.GetTaskLog(alertType, alert.ID)
		if err != nil {
			global.LOG.Errorf("task log record not found, err: %v", err)
		}
		if newDate.IsZero() || calculateMinutesDifference(newDate) > ResourceAlertInterval {
			for _, m := range methods {
				m = strings.TrimSpace(m)
				switch m {
				case constant.SMS:
					if !alertUtil.CheckSMSSendLimit(constant.SMS) {
						continue
					}
					todayCount, isValid := canSendAlertToday(alertType, quotaType, alert.SendCount, constant.SMS)
					if !isValid {
						continue
					}
					var create = dto.AlertLogCreate{
						Type:    alertType,
						AlertId: alert.ID,
						Count:   todayCount + 1,
					}
					_ = xpack.CreateSMSAlertLog(alertType, alert, create, quotaType, params, constant.SMS)
					alertUtil.CreateNewAlertTask(quota, alertType, quotaType, constant.SMS)
					global.LOG.Info("ssh login alert sms push successful")
				case constant.Email:
					todayCount, isValid := canSendAlertToday(alertType, quotaType, alert.SendCount, constant.Email)
					if !isValid {
						continue
					}
					var create = dto.AlertLogCreate{
						Type:    alertType,
						AlertId: alert.ID,
						Count:   todayCount + 1,
					}
					alertDetail := alertUtil.ProcessAlertDetail(alertInfo, quotaType, params, constant.Email)
					alertRule := alertUtil.ProcessAlertRule(alert)
					create.AlertRule = alertRule
					create.AlertDetail = alertDetail
					transport := xpack.LoadRequestTransport()
					_ = alertUtil.CreateEmailAlertLog(create, alertInfo, params, transport)
					alertUtil.CreateNewAlertTask(quota, alertType, quotaType, constant.Email)
					global.LOG.Info("ssh login alert email push successful")
				default:
				}
			}
		}
	}
}

func sendAlerts(alert dto.AlertDTO, alertType, quota, quotaType string, params []dto.Param) {
	methods := strings.Split(alert.Method, ",")
	newDate, err := alertRepo.GetTaskLog(alertType, alert.ID)
	if err != nil {
		global.LOG.Errorf("task log record not found, err: %v", err)
	}
	if newDate.IsZero() || calculateMinutesDifference(newDate) > ResourceAlertInterval {
		for _, m := range methods {
			m = strings.TrimSpace(m)
			switch m {
			case constant.SMS:
				if !alertUtil.CheckSMSSendLimit(constant.SMS) {
					continue
				}
				todayCount, isValid := canSendAlertToday(alertType, quotaType, alert.SendCount, constant.SMS)
				if !isValid {
					continue
				}
				create := dto.AlertLogCreate{
					Type:    alertType,
					AlertId: alert.ID,
					Count:   todayCount + 1,
				}
				_ = xpack.CreateSMSAlertLog(alertType, alert, create, quotaType, params, constant.SMS)
				alertUtil.CreateNewAlertTask(quota, alertType, quotaType, constant.SMS)
				global.LOG.Infof("%s alert sms push successful", alertType)

			case constant.Email:
				todayCount, isValid := canSendAlertToday(alertType, quotaType, alert.SendCount, constant.Email)
				if !isValid {
					continue
				}
				create := dto.AlertLogCreate{
					Type:    alertType,
					AlertId: alert.ID,
					Count:   todayCount + 1,
				}
				alertInfo := alert
				alertInfo.Type = alertType
				create.AlertRule = alertUtil.ProcessAlertRule(alert)
				create.AlertDetail = alertUtil.ProcessAlertDetail(alertInfo, quotaType, params, constant.Email)
				transport := xpack.LoadRequestTransport()
				_ = alertUtil.CreateEmailAlertLog(create, alertInfo, params, transport)
				alertUtil.CreateNewAlertTask(quota, alertType, quotaType, constant.Email)
				global.LOG.Infof("%s alert email push successful", alertType)
			}
		}
	}
}
