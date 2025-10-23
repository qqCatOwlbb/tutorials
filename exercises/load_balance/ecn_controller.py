#!/usr/bin/env python3
# -*- coding: utf-8 -*- SPDX-License-Identifier: 
# Apache-2.0
import argparse 
import json 
import os 
import sys 
import grpc
from time import sleep
# Import P4Runtime lib from parent utils dir 
# 导入P4Runtime库，假设你已经将utils文件夹添加到了PYTHONPATH中
sys.path.append( 
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/')) 
import p4runtime_lib.bmv2 
import p4runtime_lib.helper 
from p4runtime_lib.switch import ShutdownAllSwitchConnections 
from p4runtime_lib.error_utils import printGrpcError 
def write_ecn_config_rule(p4info_helper, sw, threshold):
    """ 安装ECN队列长度阈值配置规则。
    
    :param p4info_helper: P4Info 助手 param sw: 
    :交换机连接对象 param threshold: 队列长度阈值 
    :(bit<19>)
    """
    # 构建默认动作的表项，目标表为 MyIngress.ecn_config 
    # 注意: 使用 default_action=True 
    # 可以在没有匹配键的情况下插入/修改默认条目。
    table_entry = p4info_helper.buildTableEntry( 
        table_name="MyIngress.ecn_config", 
        default_action=True, 
        action_name="MyIngress.set_ecn_threshold", 
        action_params={
            "threshold": threshold,
        })
    # 发送请求，更新默认条目
    sw.WriteTableEntry(table_entry) 
    print(f"已在 {sw.name} 上安装 ECN 阈值配置: {threshold}")
def write_ipv4_lpm_rules(p4info_helper, sw, runtime_rules):
    """ 为给定交换机安装 ipv4_lpm 表的路由规则。
    
    :param p4info_helper: P4Info 助手 param sw: 
    :交换机连接对象 param runtime_rules: 
    :包含运行时表项的字典
    """ 
    for entry in runtime_rules.get("table_entries", 
    []):
        if entry["table"] == "MyIngress.ipv4_lpm":
            # 路由规则使用硬编码的优先级 1
            table_entry = p4info_helper.buildTableEntry( 
                table_name=entry["table"], 
                match_fields=entry["match"], 
                action_name=entry["action_name"], 
                action_params=entry["action_params"], 
            ) 
            sw.WriteTableEntry(table_entry) 
            match_str = ", ".join([f"{k}: {v}" for k, v in entry['match'].items()]) 
            param_str = ", ".join([f"{k}: {v}" for k, v in entry['action_params'].items()]) 
            print(f"已在 {sw.name} 上安装 IPv4 规则: {match_str} -> {entry['action_name']}({param_str})")
def read_runtime_file(filepath): 
    """读取并加载 JSON 运行时文件内容。"""
    # 假设控制器的运行目录在 exercises/ecn/
    full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filepath) 
    try:
        with open(full_path, 'r') as f: 
            return json.load(f)
    except Exception as e: 
        print(f"加载运行时文件 {full_path} 错误: {e}") 
        return {}
def main(p4info_file_path, bmv2_file_path, ecn_threshold):
    # 实例化 P4Runtime 助手
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    # 加载原有的静态路由规则，用于动态下发
    s1_rules = read_runtime_file("s1-runtime.json") 
    s2_rules = read_runtime_file("s2-runtime.json") 
    s3_rules = read_runtime_file("s3-runtime.json") 
    try:
        # 创建交换机连接对象
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection( 
            name='s1', 
            address='127.0.0.1:50051', 
            device_id=0, 
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection( 
            name='s2', 
            address='127.0.0.1:50052', 
            device_id=1, 
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection( 
            name='s3', 
            address='127.0.0.1:50053', 
            device_id=2, 
            proto_dump_file='logs/s3-p4runtime-requests.txt')
        
        switches = [s1, s2, s3] 
        switch_rules = {s1: s1_rules, s2: s2_rules, s3: s3_rules}
        # 发送主仲裁更新消息，确立控制器的主身份
        for sw in switches: 
            sw.MasterArbitrationUpdate()
            
        # 在交换机上安装 P4 程序
        for sw in switches: 
            sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path=bmv2_file_path) 
            print(f"已在 {sw.name} 上安装 P4 程序")
        # 写入 ECN 配置和 IPv4 路由规则
        for sw in switches:
            # 1. 写入 ECN 阈值配置
            write_ecn_config_rule(p4info_helper, sw, ecn_threshold)
            
            # 2. 写入 IPv4 LPM 路由规则
            write_ipv4_lpm_rules(p4info_helper, sw, switch_rules[sw])
        # 保持控制器运行，以维持主身份
        print("\n控制器正在运行，阈值已配置。请回到Mininet终端进行测试。按下 Ctrl-C 停止。") 
        while True:
            sleep(1) 
    except KeyboardInterrupt: 
        print("停止控制器。")
    except grpc.RpcError as e: 
        printGrpcError(e) 
    ShutdownAllSwitchConnections()
if __name__ == '__main__': 
    parser = argparse.ArgumentParser(description='P4Runtime ECN Controller') 
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False, 
                        default='./build/ecn.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", 
                        required=False, 
                        default='./build/ecn.json')
    parser.add_argument('--threshold', help='ECN队列长度阈值 (bit<19>)，例如: 5',
                        type=int, action="store", 
                        required=False, default=5)
    args = parser.parse_args() 
    if not os.path.exists("build/ecn.json") or not os.path.exists(args.bmv2_json):
        print("\n请先运行 'make' 命令编译 P4 程序。") 
        sys.exit(1)
    
    # 确保阈值在有效范围内 (bit<19> 最大值为 2^19 - 1 = 
    # 524287)
    ecn_threshold_val = max(0, min(args.threshold, 524287))
        
    main(args.p4info, args.bmv2_json, ecn_threshold_val)
