import tornado


class CliServer(object):

    """
    The CliServer is created only when the user specifies that s-he doesn't
    want to use the WebUI.

    This can be specify with the '--nowebui' argument in the CLI.
    """

    def __init__(self, core):
        self.manager_cron = tornado.ioloop.PeriodicCallback(core.WorkerManager.manage_workers, 2000)

    def start(self):
        try:
            self.manager_cron.start()
            tornado.ioloop.IOLoop.instance().start()
        except KeyboardInterrupt:
            pass
