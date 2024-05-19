import wx
import logging
import wx.lib.agw.flatnotebook as FNB
import os

from antivir import Antivirus

class MainFrame(wx.Frame):
    def __init__(self, parent, title, virus_total_api_key):
        super(MainFrame, self).__init__(parent, title=title, size=(800, 600))
        self.antivirus = Antivirus(virus_total_api_key)

        panel = wx.Panel(self)
        panel.SetBackgroundColour('#f8f9fa')

        hbox = wx.BoxSizer(wx.HORIZONTAL)

        self.sidebar = wx.Panel(panel, size=(100, -1))
        self.sidebar.SetBackgroundColour('#007bff')
        self.sidebar.Bind(wx.EVT_LEFT_DOWN, self.toggle_sidebar)

        vbox_sidebar = wx.BoxSizer(wx.VERTICAL)

        self.create_rounded_button(vbox_sidebar, 'Proteção', self.start_protection, 'icons/shield.png')
        self.create_rounded_button(vbox_sidebar, 'Configurações', self.show_settings, 'icons/settings.png')
        self.create_rounded_button(vbox_sidebar, 'Relatório', self.show_report, 'icons/report.png')

        self.sidebar.SetSizer(vbox_sidebar)
        hbox.Add(self.sidebar, flag=wx.EXPAND)

        vbox = wx.BoxSizer(wx.VERTICAL)

        title_text = wx.StaticText(panel, label="Antivirus")
        title_text.SetFont(wx.Font(20, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD))
        title_text.SetForegroundColour('#333333')
        vbox.Add(title_text, flag=wx.ALIGN_CENTER_HORIZONTAL|wx.TOP|wx.BOTTOM, border=20)

        notebook = FNB.FlatNotebook(panel, size=(-1, -1), style=FNB.FNB_NODRAG)
        notebook.SetBackgroundColour('#ffffff')
        notebook.SetTabAreaColour('#f8f9fa')
        notebook.SetNonActiveTabTextColour('#333333')
        vbox.Add(notebook, proportion=1, flag=wx.EXPAND|wx.ALL, border=20)

        notebook.AddPage(wx.Panel(notebook), "Detecção de Vírus", True)
        notebook.AddPage(wx.Panel(notebook), "Quarentena")
        notebook.AddPage(wx.Panel(notebook), "Configurações")

        hbox.Add(vbox, proportion=1, flag=wx.EXPAND|wx.ALL, border=20)

        panel.SetSizer(hbox)

        # StatusBar
        self.CreateStatusBar()
        self.SetStatusText("Pronto")

        # Menu Bar
        menubar = wx.MenuBar()
        file_menu = wx.Menu()
        file_menu.Append(wx.ID_EXIT, "&Sair", "Sair do programa")
        menubar.Append(file_menu, "&Arquivo")
        self.SetMenuBar(menubar)

        # Event Handlers
        self.Bind(wx.EVT_MENU, self.on_exit, id=wx.ID_EXIT)

        self.Show()

    def create_rounded_button(self, sizer, label, callback, icon_path=None):
        button = wx.BitmapButton(self.sidebar, -1, wx.Bitmap(icon_path, wx.BITMAP_TYPE_PNG), style=wx.NO_BORDER)
        button.SetForegroundColour('#ffffff')
        button.SetBackgroundColour('#007bff')
        button.Bind(wx.EVT_BUTTON, callback)

        sizer.Add(button, flag=wx.EXPAND|wx.ALL, border=2)

    def toggle_sidebar(self, event):
        if self.sidebar.GetSize().GetWidth() == 100:
            self.sidebar.SetSize((50, -1))
        else:
            self.sidebar.SetSize((100, -1))

    def start_protection(self, event):
        logging.info("Iniciando proteção...")
        # Adicionar a lógica para iniciar a proteção aqui

    def show_settings(self, event):
        logging.info("Abrindo configurações...")
        # Adicionar a lógica para mostrar as configurações aqui

    def show_report(self, event):
        logging.info("Mostrando relatório...")
        # Adicionar a lógica para mostrar o relatório aqui

    def on_exit(self, event):
        self.Close()

def main():
    logging.basicConfig(level=logging.INFO)

    app = wx.App()

    MainFrame(None, title='Antivirus GUI', virus_total_api_key="c4d18d390127a3b6b4d7f55375adcbb0cb42b83a66d2e62db2bfdad3ee4795e2")
    
    # Define o ícone da janela principal
    app_icon = wx.Icon('icons/antiviruslogo.ico', wx.BITMAP_TYPE_ICO)
    app.GetTopWindow().SetIcon(app_icon)
    
    app.MainLoop()

if __name__ == "__main__":
    main()