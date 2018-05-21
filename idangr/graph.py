from context import load_project

def dict_ddg(function_addr):
    project = load_project()
    cfg = project.analysis.CFGAccurate(start=function_addr, context_sensitivity_level=2, keep_state=True))
    ddg = project.analysis.DDG(cfg)
    
