## 简单介绍
* arvo-allinone.py全流程脚本，包括拉下docker、运行poc、生成修复patch、改变项目build文件以及arvo文件加入tracepc标记收集程序cov、生成prompt文本文件等。可能针对其他漏洞运行脚本会出现错误、可能需要根据实际环境需要修改。
* analysis-trace.py，生成callgraph、分析漏洞堆栈的调用关系，可能需要根据实际环境需要修改。
* environment未给出，不过需要的库很少自行安装就行了。