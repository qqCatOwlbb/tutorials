# File: p4lang/tutorials/tutorials-master/exercises/ecn/Makefile

# SPDX-License-Identifier: Apache-2.0
BMV2_SWITCH_EXE = simple_switch_grpc

include ../../utils/Makefile

# 覆盖默认的 'run' 目标，改为只在前景运行 Mininet。
.PHONY: run
run: build run-controller

# 移除后台运行符号 & 和有问题的 sudo fg
run-controller:
	@echo ""
	@echo "======================================================================"
	@echo "Mininet 拓扑启动中..."
	@echo "请注意：您需要在另一个终端窗口中启动控制器，以便下发动态ECN阈值。"
	@echo "1. Mininet 启动并出现 'mininet>' 提示符后，请立即在**新的终端窗口**中运行控制器，设置您想要的阈值（例如 5）："
	@echo "   cd ~/tutorials/exercises/ecn"
	@echo "   python3 ecn_controller.py --threshold 5"
	@echo "2. 控制器成功启动后，您可以在这个 Mininet 终端中进行流量测试。"
	@echo "======================================================================"
	@echo ""
	# 启动 Mininet 拓扑，并在前台等待用户退出 CLI，这避免了使用 'fg'
	sudo PATH=$(PATH) ${P4_EXTRA_SUDO_OPTS} python3 $(RUN_SCRIPT) -t $(TOPO) -j $(DEFAULT_JSON) -b $(BMV2_SWITCH_EXE)