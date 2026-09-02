package multiagent

import "cyberstrike-ai/internal/config"

const defaultAgentMaxIterations = config.DefaultAgentMaxIterations

// agentMaxIterations uses the same 30-iteration default as the configuration UI.
func agentMaxIterations(appCfg *config.Config) int {
	if appCfg != nil && appCfg.Agent.MaxIterations > 0 {
		return appCfg.Agent.MaxIterations
	}
	return defaultAgentMaxIterations
}

// resolveMaxIterations 统一迭代上限：Markdown/子代理 front matter 中 max_iterations>0 可单独覆盖，否则使用 agent.max_iterations。
// multi_agent.max_iteration 与 sub_agent_max_iterations 已废弃，不再参与计算。
func resolveMaxIterations(appCfg *config.Config, markdownOverride int) int {
	if markdownOverride > 0 {
		return markdownOverride
	}
	return agentMaxIterations(appCfg)
}
