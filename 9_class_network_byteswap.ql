import cpp

class NetworkByteSwap extends Expr {

    NetworkByteSwap() {
        exists(
            MacroInvocation mi | 
            this = mi.getExpr() and mi.getMacroName() in ["ntohs", "ntohl", "ntohll"]
        )
    }
}

from NetworkByteSwap nbs
select nbs, "Network byte swap"