package utils

import (
	"fmt"
	"strings"
	"time"
)

// PerformanceStats 性能统计结构体
type PerformanceStats struct {
	OperationName string        // 操作名称
	TotalCount    int           // 总次数
	SuccessCount  int           // 成功次数
	FailCount     int           // 失败次数
	Durations     []time.Duration // 每次操作的耗时
	StartTime     time.Time     // 开始时间
	EndTime       time.Time     // 结束时间
}

// NewPerformanceStats 创建新的性能统计对象
func NewPerformanceStats(operationName string) *PerformanceStats {
	return &PerformanceStats{
		OperationName: operationName,
		TotalCount:    0,
		SuccessCount:  0,
		FailCount:     0,
		Durations:     make([]time.Duration, 0),
		StartTime:     time.Now(),
	}
}

// RecordSuccess 记录成功操作
func (ps *PerformanceStats) RecordSuccess(duration time.Duration) {
	ps.TotalCount++
	ps.SuccessCount++
	ps.Durations = append(ps.Durations, duration)
}

// RecordFailure 记录失败操作
func (ps *PerformanceStats) RecordFailure(duration time.Duration) {
	ps.TotalCount++
	ps.FailCount++
	ps.Durations = append(ps.Durations, duration)
}

// GetTotalDuration 获取总耗时
func (ps *PerformanceStats) GetTotalDuration() time.Duration {
	if len(ps.Durations) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range ps.Durations {
		total += d
	}
	return total
}

// GetAverageDuration 获取平均耗时
func (ps *PerformanceStats) GetAverageDuration() time.Duration {
	if len(ps.Durations) == 0 {
		return 0
	}
	return ps.GetTotalDuration() / time.Duration(len(ps.Durations))
}

// GetMinDuration 获取最小耗时
func (ps *PerformanceStats) GetMinDuration() time.Duration {
	if len(ps.Durations) == 0 {
		return 0
	}
	min := ps.Durations[0]
	for _, d := range ps.Durations[1:] {
		if d < min {
			min = d
		}
	}
	return min
}

// GetMaxDuration 获取最大耗时
func (ps *PerformanceStats) GetMaxDuration() time.Duration {
	if len(ps.Durations) == 0 {
		return 0
	}
	max := ps.Durations[0]
	for _, d := range ps.Durations[1:] {
		if d > max {
			max = d
		}
	}
	return max
}

// GetSuccessRate 获取成功率（百分比）
func (ps *PerformanceStats) GetSuccessRate() float64 {
	if ps.TotalCount == 0 {
		return 0.0
	}
	return float64(ps.SuccessCount) / float64(ps.TotalCount) * 100.0
}

// Finish 完成统计，记录结束时间
func (ps *PerformanceStats) Finish() {
	ps.EndTime = time.Now()
}

// GetElapsedTime 获取总经过时间
func (ps *PerformanceStats) GetElapsedTime() time.Duration {
	return ps.EndTime.Sub(ps.StartTime)
}

// PrintSummary 打印性能统计摘要
func (ps *PerformanceStats) PrintSummary() {
	ps.Finish()
	
	separator := strings.Repeat("=", 80)
	fmt.Println("\n" + separator)
	fmt.Printf("【%s】性能测试报告\n", ps.OperationName)
	fmt.Println(separator)
	
	fmt.Printf("总操作次数:     %d\n", ps.TotalCount)
	fmt.Printf("成功次数:       %d\n", ps.SuccessCount)
	fmt.Printf("失败次数:       %d\n", ps.FailCount)
	fmt.Printf("成功率:         %.2f%%\n", ps.GetSuccessRate())
	
	if len(ps.Durations) > 0 {
		fmt.Println("\n响应时间统计:")
		fmt.Printf("  总耗时:       %v\n", ps.GetTotalDuration())
		fmt.Printf("  平均耗时:     %v\n", ps.GetAverageDuration())
		fmt.Printf("  最小耗时:     %v\n", ps.GetMinDuration())
		fmt.Printf("  最大耗时:     %v\n", ps.GetMaxDuration())
	}
	
	fmt.Printf("\n总经过时间:     %v\n", ps.GetElapsedTime())
	fmt.Println(separator)
}

// PrintDetailedReport 打印详细的性能报告（包含每次操作的耗时）
func (ps *PerformanceStats) PrintDetailedReport() {
	ps.PrintSummary()
	
	if len(ps.Durations) > 0 {
		fmt.Println("\n详细响应时间列表:")
		for i, duration := range ps.Durations {
			status := "成功"
			if i >= ps.SuccessCount {
				status = "失败"
			}
			fmt.Printf("  操作 %d: %v (%s)\n", i+1, duration, status)
		}
	}
}

