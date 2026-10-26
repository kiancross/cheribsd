PROG=	cheribsdtest-small-stack
MAN=

# A stack far smaller than MAXSSIZ, for colocation_coexecve_small_stack.
LDFLAGS+=	-Wl,-z,stack-size=1048576

.include <bsd.prog.mk>
