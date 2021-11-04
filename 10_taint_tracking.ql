import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {

    NetworkByteSwap() {
        exists(
            MacroInvocation mi | 
            this = mi.getExpr() and mi.getMacroName() in ["ntohs", "ntohl", "ntohll"]
        )
    }
}

class MemcpyCall extends FunctionCall {
    MemcpyCall() {
        this.getTarget().getName() = "memcpy"
    }
}

class Config extends TaintTracking::Configuration {
    Config() {
        this = "NetworkToMemFuncLength"
    }

    override predicate isSource(DataFlow::Node source) {
        exists(
            NetworkByteSwap nbs | source.asExpr() = nbs
        )
    }
    
    override predicate isSink(DataFlow::Node sink) {
        exists(
            MemcpyCall mc | mc.getArgument(2) = sink.asExpr()
        )
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, "Network byte swap flows to memcpy"
