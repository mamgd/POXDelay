from datetime import datetime

def launch (postfix=datetime.now().strftime("%Y%m%d%H%M%S")):
        from log.level import launch
        launch(DEBUG=True)

        from samples.pretty_log import launch
        launch()

        from openflow.keepalive import launch
        launch(interval=15) # 15 seconds

        from openflow.discovery import launch
        launch()

        #we solved the flooding-problem in l2_multi_withstate
        #from openflow.spanning_tree import launch
        #launch(no_flood = True, hold_down = True)

        from POXDelay.my_pox import launch
        launch()

        from POXDelay.monitoring import launch
        launch(postfix=postfix)
