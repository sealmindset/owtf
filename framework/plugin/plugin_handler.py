#!/usr/bin/env python
"""

owtf is an OWASP+PTES-focused try to unite great tools and facilitate pen testing
Copyright (c) 2011, Abraham Aranguren <name.surname@gmail.com> Twitter: @7a_ http://7-a.org
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright owner nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The PluginHandler is in charge of running all plugins taking into account the
chosen settings.
"""

import os
import imp
import logging

from ptp import PTP
from ptp.libptp.exceptions import PTPError

from framework.lib.exceptions import FrameworkAbortException, \
                                     PluginAbortException, \
                                     UnreachableTargetException
from framework.lib.general import *
from framework.plugin.scanner import Scanner


INTRO_BANNER_GENERAL = """
Short Intro:
Current Plugin Groups:
- web: For web assessments or when net plugins find a port that "speaks HTTP"
- net: For network assessments, discovery and port probing
- aux: Auxiliary plugins, to automate miscelaneous tasks
"""

INTRO_BANNER_WEB_PLUGIN_TYPE = """
WEB Plugin Types:
- Passive Plugins: NO requests sent to target
- Semi Passive Plugins: SOME "normal/legitimate" requests sent to target
- Active Plugins: A LOT OF "bad" requests sent to target (You better have permission!)
- Grep Plugins: NO requests sent to target. 100% based on transaction searches and plugin output parsing. Automatically run after semi_passive and active in default profile.
"""

class PluginHandler:
    def __init__(self, CoreObj, Options):
        self.Core = CoreObj
        self.plugin_count = 0
        #This should be dynamic from filesystem:
        #self.PluginGroups = [ 'web', 'net', 'aux' ]
        #self.PluginTypes = [ 'passive', 'semi_passive', 'active', 'grep' ]
        #self.AllowedPluginTypes = self.GetAllowedPluginTypes(Options['PluginType'].split(','))
        #self.Simulation, self.Scope, self.PluginGroup, self.Algorithm, self.ListPlugins = [ Options['Simulation'], Options['Scope'], Options['PluginGroup'], Options['Algorithm'], Options['ListPlugins'] ]
        self.Simulation, self.Scope, self.PluginGroup = [ Options['Simulation'], Options['Scope'], Options['PluginGroup'] ]
        self.scanner = Scanner(self.Core)
        self.showOutput = True

    def ValidateAndFormatPluginList(self, plugin_codes):
        """Validate the plugin details by checking if they exist.

        :param list plugin_codes: OWTF plugin codes/names to be validated.

        :return: validated plugin codes.
        :rtype: list

        """
        # Ensure there is always a list to iterate from! :)
        if not plugin_codes:
            return []
        valid_plugin_codes = []
        for code in plugin_codes:
            found = False
            if self.Core.DB.Plugin.is_valid_plugin(code=code):
                valid_plugin_codes.append(code)
                found = True
            if not found:
                self.Core.Error.FrameworkAbort(
                    "The code '%s' is not a valid plugin, please "
                    "use the -l option to see available plugin "
                    "codes" % code)
        return valid_plugin_codes # Return list of Codes

    def PluginAlreadyRun(self, PluginInfo):
        return self.Core.DB.POutput.PluginAlreadyRun(PluginInfo)

    def NormalRequestsAllowed(self):
        #AllowedPluginTypes = self.Core.Config.GetAllowedPluginTypes('web')
        #GetAllowedPluginTypes('web')
        AllowedPluginTypes = self.Core.Config.Plugin.GetAllowedTypes('web')
        return 'semi_passive' in AllowedPluginTypes or 'active' in AllowedPluginTypes

    def RequestsPossible(self):
        # Even passive plugins will make requests to external resources
        #return [ 'grep' ] != self.Core.Config.GetAllowedPluginTypes('web')
        return [ 'grep' ] != self.Core.DB.Plugin.GetTypesForGroup('web')

    def DumpOutputFile(self, Filename, Contents, Plugin, RelativePath=False):
        SaveDir = self.GetPluginOutputDir(Plugin)
        abs_path = self.Core.DumpFile(Filename, Contents, SaveDir)
        if RelativePath:
            return(os.path.relpath(abs_path, self.Core.Config.GetOutputDirForTargets()))
        return(abs_path)

    def RetrieveAbsPath(self, RelativePath):
        return(os.path.join(self.Core.Config.GetOutputDirForTargets(), RelativePath))

    def GetPluginOutputDir(self, Plugin): # Organise results by OWASP Test type and then active, passive, semi_passive
        #print "Plugin="+str(Plugin)+", Partial url ..="+str(self.Core.Config.Get('partial_url_output_path'))+", TARGET="+self.Core.Config.Get('TARGET')
        if ((Plugin['group'] == 'web') or (Plugin['group'] == 'net')):
            return os.path.join(self.Core.DB.Target.GetPath('partial_url_output_path'), WipeBadCharsForFilename(Plugin['title']), Plugin['type'])
        elif Plugin['group'] == 'aux':
            return os.path.join(self.Core.Config.Get('AUX_OUTPUT_PATH'), WipeBadCharsForFilename(Plugin['title']), Plugin['type'])

    def exists(self, directory):
        return os.path.exists(directory)

    def GetModule(self, ModuleName, ModuleFile, ModulePath):# Python fiddling to load a module from a file, there is probably a better way...
        f, Filename, desc = imp.find_module(ModuleFile.split('.')[0], [ModulePath]) #ModulePath = os.path.abspath(ModuleFile)
        return imp.load_module(ModuleName, f, Filename, desc)

    def IsActiveTestingPossible(self): # Checks if 1 active plugin is enabled = active testing possible:
        Possible = False
        #for PluginType, PluginFile, Title, Code, ReferenceURL in self.Core.Config.GetPlugins(): # Processing Loop
        #for PluginType, PluginFile, Title, Code in self.Core.Config.Plugin.GetOrder(self.PluginGroup):
        for Plugin in self.Core.Config.Plugin.GetOrder(self.PluginGroup):
            if self.IsChosenPlugin(Plugin) and Plugin['type'] == 'active':
                Possible = True
                break
        return Possible

    def force_overwrite(self):
        #return self.Core.Config.Get('FORCE_OVERWRITE')
        return False

    def GetPluginFullPath(self, PluginDir, Plugin):
        return PluginDir+"/"+Plugin['type']+"/"+Plugin['file'] # Path to run the plugin

    def RunPlugin(self, PluginDir, Plugin, save_output=True):
        PluginPath = self.GetPluginFullPath(PluginDir, Plugin)
        (Path, Name) = os.path.split(PluginPath)
        #(Name, Ext) = os.path.splitext(Name)
        #self.Core.DB.Debug.Add("Running Plugin -> Plugin="+str(Plugin)+", PluginDir="+str(PluginDir))
        PluginOutput = self.GetModule("", Name, Path+"/").run(self.Core, Plugin)
        #if save_output:
            #print(PluginOutput)
            #self.SavePluginInfo(PluginOutput, Plugin) # Timer retrieved here
        return PluginOutput


    @staticmethod
    def rank_plugin(output, pathname):
        """Rank the current plugin results using PTP.

        Returns the ranking value.

        """
        def extract_metasploit_modules(cmd):
            """Extract the metasploit modules contained in the plugin output.

            Returns the list of (module name, output file) found, an empty list
            otherwise.

            """
            return [
                (
                    output['output'].get('ModifiedCommand', '').split(' ')[3],
                    os.path.basename(
                        output['output'].get('RelativeFilePath', ''))
                )
                for output in cmd
                if ('output' in output and
                    'metasploit' in output['output'].get('ModifiedCommand', ''))]

        msf_modules = None
        if output:  # Try to retrieve metasploit modules that were used.
            msf_modules = extract_metasploit_modules(output)
        owtf_rank = -1  # Default ranking value set to Unknown.
        try:
            parser = PTP()
            if msf_modules:  # PTP needs to know the msf module name.
                for module in msf_modules:
                    parser.parse(
                        pathname=pathname,
                        filename=module[1],  # Path to output file.
                        plugin=module[0])  # Metasploit module name.
                    owtf_rank = max(
                        owtf_rank,
                        parser.get_highest_ranking())
            else:  # Otherwise use the auto-detection mode.
                parser.parse(pathname=pathname)
                owtf_rank = parser.get_highest_ranking()
        except PTPError:  # Not supported tool or report not found.
            pass
        return owtf_rank

    def ProcessPlugin(self, plugin_dir, plugin, status={}):
        """Process a plugin from running to ranking.

        :param str plugin_dir: Path to the plugin directory.
        :param dict plugin: The plugin dictionary with all the information.
        :param dict status: Running status of the plugin.

        :return: The output generated by the plugin when run.
        :return: None if the plugin was not run.
        :rtype: list

        """
        # Save how long it takes for the plugin to run.
        self.Core.Timer.start_timer('Plugin')
        plugin['start'] = self.Core.Timer.get_start_date_time('Plugin')
        # Use relative path from targets folders while saving
        plugin['output_path'] = os.path.relpath(
            self.GetPluginOutputDir(plugin),
            self.Core.Config.GetOutputDirForTargets())
        status['AllSkipped'] = False  # A plugin is going to be run.
        plugin['status'] = 'Running'
        self.plugin_count += 1
        logging.info(
            '_' * 10 + ' %d - Target: %s -> Plugin: %s (%s/%s) ' + '_' * 10,
            self.plugin_count,
            self.Core.DB.Target.GetTargetURL(),
            plugin['title'],
            plugin['group'],
            plugin['type'])
        # Skip processing in simulation mode, but show until line above
        # to illustrate what will run
        if self.Simulation:
            return None
        # DB empty => grep plugins will fail, skip!!
        if ('grep' == plugin['type'] and
                self.Core.DB.Transaction.NumTransactions() == 0):
            logging.info(
                'Skipped - Cannot run grep plugins: '
                'The Transaction DB is empty')
            return None
        output = None
        status_msg = ''
        partial_output = []
        abort_reason = ''
        try:
            output = self.RunPlugin(plugin_dir, plugin)
            status_msg = 'Successful'
            status['SomeSuccessful'] = True
        except KeyboardInterrupt:
            # Just explain why crashed.
            status_msg = 'Aborted'
            abort_reason = 'Aborted by User'
            status['SomeAborted (Keyboard Interrupt)'] = True
        except SystemExit:
            # Abort plugin processing and get out to external exception
            # handling, information saved elsewhere.
            raise SystemExit
        except PluginAbortException as PartialOutput:
            status_msg = 'Aborted (by user)'
            partial_output = PartialOutput.parameter
            abort_reason = 'Aborted by User'
            status['SomeAborted'] = True
        except UnreachableTargetException as PartialOutput:
            status_msg = 'Unreachable Target'
            partial_output = PartialOutput.parameter
            abort_reason = 'Unreachable Target'
            status['SomeAborted'] = True
        except FrameworkAbortException as PartialOutput:
            status_msg = 'Aborted (Framework Exit)'
            partial_output = PartialOutput.parameter
            abort_reason = 'Framework Aborted'
        # TODO: Handle this gracefully
        # except:
        #     Plugin["status"] = "Crashed"
        #     cprint("Crashed")
        #     self.SavePluginInfo(self.Core.Error.Add("Plugin "+Plugin['Type']+"/"+Plugin['File']+" failed for target "+self.Core.Config.Get('TARGET')), Plugin) # Try to save something
        #     TODO: http://blog.tplus1.com/index.php/2007/09/28/the-python-logging-module-is-much-better-than-print-statements/
        finally:
            plugin['status'] = status_msg
            plugin['end'] = self.Core.Timer.get_end_date_time('Plugin')
            plugin['owtf_rank'] = self.rank_plugin(
                output,
                self.GetPluginOutputDir(plugin))
            if status_msg == 'Successful':
                self.Core.DB.POutput.SavePluginOutput(plugin, output)
            else:
                self.Core.DB.POutput.SavePartialPluginOutput(
                    plugin,
                    partial_output,
                    abort_reason)
            if status_msg == 'Aborted':
                self.Core.Error.UserAbort('Plugin')
            if abort_reason == 'Framework Aborted':
                self.Core.finish()
        return output

    def ProcessPlugins(self):
        status = {
            'SomeAborted': False,
            'SomeSuccessful': False,
            'AllSkipped': True}
        if self.PluginGroup in ['web', 'aux', 'net']:
            self.ProcessPluginsForTargetList(
                self.PluginGroup,
                status,
                self.Core.DB.Target.GetAll("id"))
        return status

    def GetPluginGroupDir(self, PluginGroup):
        PluginDir = self.Core.Config.FrameworkConfigGet('PLUGINS_DIR')+PluginGroup
        return PluginDir

    def SwitchToTarget(self, Target):
        self.Core.DB.Target.SetTarget(Target) # Tell Target DB that all Gets/Sets are now Target-specific

    def get_plugins_in_order_for_PluginGroup(self, PluginGroup):
        return self.Core.Config.Plugin.GetOrder(PluginGroup)

    def get_plugins_in_order(self, PluginGroup):
        return self.Core.Config.Plugin.GetOrder(PluginGroup)

    def ProcessPluginsForTargetList(self, PluginGroup, Status, TargetList): # TargetList param will be useful for netsec stuff to call this
        PluginDir = self.GetPluginGroupDir(PluginGroup)
        if PluginGroup == 'net':
            portwaves =  self.Core.Config.Get('PORTWAVES')
            waves = portwaves.split(',')
            waves.append('-1')
            lastwave=0
            for Target in TargetList: # For each Target
                self.scanner.scan_network(Target)
                #Scanning and processing the first part of the ports
                for i in range(1):
                    ports = self.Core.Config.GetTcpPorts(lastwave,waves[i])
                    print "probing for ports" + str(ports)
                    http = self.scanner.probe_network(Target, 'tcp', ports)
                    # Tell Config that all Gets/Sets are now
                    # Target-specific.
                    self.SwitchToTarget(Target)
                    for Plugin in self.get_plugins_in_order_for_PluginGroup(PluginGroup):
                        self.ProcessPlugin(PluginDir, Plugin, Status)
                    lastwave = waves[i]
                    for http_ports in http:
                        if http_ports == '443':
                            self.ProcessPluginsForTargetList(
                                'web', {
                                    'SomeAborted': False,
                                    'SomeSuccessful': False,
                                    'AllSkipped': True},
                                {'https://' + Target.split('//')[1]}
                                )
                        else:
                            self.ProcessPluginsForTargetList(
                                'web', {
                                    'SomeAborted': False,
                                    'SomeSuccessful': False,
                                    'AllSkipped': True},
                                {Target}
                                )
        else:
            pass
            #self.WorkerManager.startinput()
            #self.WorkerManager.fillWorkList(PluginGroup,TargetList)
            #self.WorkerManager.spawn_workers()
            #self.WorkerManager.manage_workers()
            #self.WorkerManager.poisonPillToWorkers()
            #Status = self.WorkerManager.joinWorker()
            #if 'breadth' == self.Algorithm: # Loop plugins, then targets
            #       for Plugin in self.Core.Config.Plugin.GetOrder(PluginGroup):# For each Plugin
            #               #print "Processing Plugin="+str(Plugin)
            #               for Target in TargetList: # For each Target
            #                       #print "Processing Target="+str(Target)
            #                       self.SwitchToTarget(Target) # Tell Config that all Gets/Sets are now Target-specific
            #                       self.ProcessPlugin( PluginDir, Plugin, Status )
            #elif 'depth' == self.Algorithm: # Loop Targets, then plugins
            #       for Target in TargetList: # For each Target
            #               self.SwitchToTarget(Target) # Tell Config that all Gets/Sets are now Target-specific
            #               for Plugin in self.Core.Config.Plugin.GetOrder(PluginGroup):# For each Plugin
            #                       self.ProcessPlugin( PluginDir, Plugin, Status )

    def SavePluginInfo(self, PluginOutput, Plugin):
        self.Core.DB.SaveDBs() # Save new URLs to DB after each request
        self.Core.Reporter.SavePluginReport(PluginOutput, Plugin) # Timer retrieved by Reporter

    def show_plugin_list(self, group, msg=INTRO_BANNER_GENERAL):
        if group == 'web':
            logging.info(msg + INTRO_BANNER_WEB_PLUGIN_TYPE + "\nAvailable WEB plugins:")
        elif group == 'aux':
            logging.info(msg + "\nAvailable AUXILIARY plugins:")
        elif group == 'net':
            logging.info(msg + "\nAvailable NET plugins:")
        for plugin_type in self.Core.Config.Plugin.GetTypesForGroup(group):
            self.show_plugin_types(plugin_type, group)

    def show_plugin_types(self, plugin_type, group):
        logging.info("\n" + '*' * 40 + " " + plugin_type.title().replace('_', '-') + " plugins " + '*' * 40)
        for Plugin in self.Core.Config.Plugin.GetAll(group, plugin_type):
            # 'Name' : PluginName, 'Code': PluginCode, 'File' : PluginFile, 'Descrip' : PluginDescrip } )
            LineStart = " " + Plugin['type'] + ": " + Plugin['name']
            Pad1 = "_" * (60 - len(LineStart))
            Pad2 = "_" * (20- len(Plugin['code']))
            logging.info(LineStart+Pad1+"("+Plugin['code']+")"+Pad2+Plugin['descrip'])
