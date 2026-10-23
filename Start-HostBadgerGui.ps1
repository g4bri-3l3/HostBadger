<#
.SYNOPSIS
    HostBadger in a window: collect and analyze this machine, or analyze
    snapshots already collected; add the AI summary, run the safety review,
    check for a newer HostBadger.

.DESCRIPTION
    The same steps as the guided menu (Start-HostBadger.ps1), with the answers
    as a form. It runs Collect-HostSnapshot.ps1 and HostBadger.ps1 with the
    parameters chosen here, in the background of this window, and shows what
    they print. The report is the usual HTML file, opened in the browser.

    Nothing here changes the machine. Remediation stays in the guided menu
    (Start-HostBadger.ps1, option 6), which asks for YES before anything. The
    one thing Settings can write outside HostBadger's folder is what you ask it
    to remember: GEMINI_API_KEY / NVD_API_KEY as environment variables of your
    Windows account (never in the settings file).

    Network: only what you ask for. "Download" on a catalog makes the analysis
    fetch it (the address is named next to it); "Send to Gemini" sends the
    pseudonymized findings; "Check for updates" asks the HostBadger repository
    on GitHub (git fetch of a git clone, otherwise one GET of HostBadger.ps1
    from raw.githubusercontent.com); "Update" runs git pull --ff-only origin
    main in a git clone on main with no local changes.

    The saved settings of the guided menu (output\hostbadger-settings.json,
    menu 8) fill the form. Settings writes them back, and each run saves the
    choices of the form, so the window opens as it was left.
.PARAMETER NoShow
    Build the windows without showing them, then close (used by the tests).
#>
[CmdletBinding()]
param([switch]$NoShow)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

$hbText = [System.IO.File]::ReadAllText((Join-Path $root 'HostBadger.ps1'))
$script:LocalVersion = if ($hbText -match "\`$script:HostBadgerVersion = '([\d.]+)'") { $Matches[1] } else { '?' }
$script:DefaultModel = if ($hbText -match "\[string\]\`$Model = '([^']+)'") { $Matches[1] } else { '' }
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:SettingsPath = Join-Path (Join-Path $PWD.Path 'output') 'hostbadger-settings.json'
# The badger of the report, taken from lib\Reporting.ps1 so the two stay the same.
$repText = [System.IO.File]::ReadAllText((Join-Path $root 'lib\Reporting.ps1'))
$script:Logo = if ($repText -match "(?s)\`$script:BadgerAscii = @'\r?\n(.*?)\r?\n'@") { $Matches[1] -replace "`r", '' } else { '' }

# The catalogs an analysis can use, as in the guided menu ($script:CatalogDefs in Start-HostBadger.ps1).
# Shipped: the copy in HostBadger's folder that is used offline when nothing is downloaded (none: the
# check is off without a kept copy or a download).
$script:GuiCatalogs = [ordered]@{
    Kev     = @{ Label = 'CISA KEV catalog'; Suffix = 'kev'; Online = 'KevOnline'; File = 'KevFile'; Site = 'www.cisa.gov'; Shipped = '' }
    Drivers = @{ Label = 'LOLDrivers catalog'; Suffix = 'drivers'; Online = 'DriversOnline'; File = 'DriversFile'; Site = 'www.loldrivers.io'; Shipped = 'data\vulnerable-drivers.json' }
    Eol     = @{ Label = 'Software lifecycle'; Suffix = 'eol'; Online = 'EolOnline'; File = 'EolFile'; Site = 'endoflife.date'; Shipped = 'table' }
    Choco   = @{ Label = 'Program versions'; Suffix = 'choco'; Online = 'ChocoOnline'; File = 'ChocoFile'; Site = 'community.chocolatey.org'; Shipped = '' }
    Cve     = @{ Label = 'CVEs and EPSS'; Suffix = 'cve'; Online = 'CveOnline'; File = 'CveFile'; Site = 'services.nvd.nist.gov, epss.empiricalsecurity.com'; Shipped = '' }
    Ext     = @{ Label = 'Malicious browser extensions'; Suffix = 'extensions'; Online = 'ExtensionsOnline'; File = 'ExtensionsFile'; Site = 'raw.githubusercontent.com'; Shipped = 'data\malicious-extensions.json' }
}
# The settings modes of a catalog (as in menu 8), for the Settings window.
$script:CatalogModes = [ordered]@{ kept = 'Newest kept copy, else the shipped one or none'; auto = 'Kept copy under a week old, else download'; online = 'Download at every analysis'; off = 'Never download: shipped copy or none' }

# Fix script levels: the profile tiers of data\remediation-profiles.json, with their own description.
$script:Tiers = try { ([System.IO.File]::ReadAllText((Join-Path $root 'data\remediation-profiles.json')) | ConvertFrom-Json).tiers } catch { $null }
function Get-TierText {
    param([string]$Name)
    $t = "$($script:Tiers.$Name)" -replace '^[A-Za-z]+:\s*', ''
    if ($t) { $t = $t.Substring(0, 1).ToUpper() + $t.Substring(1) }
    return $t
}
$script:Profiles = [ordered]@{
    ''                 = @{ Title = 'Only the findings'; Text = 'The safe fix of each finding: one setting, the expected value, reversible, no organizational choice.' }
    'Essential'        = @{ Title = 'Essential'; Text = (Get-TierText 'essential') }
    'Recommended'      = @{ Title = 'Recommended'; Text = (Get-TierText 'recommended') }
    'Strict'           = @{ Title = 'Strict'; Text = (Get-TierText 'strict') }
    'None'             = @{ Title = 'No fix of the findings'; Text = 'Only what is ticked below: debloat, telemetry, or both.' }
}

# ---------------- Shared look: colors and type follow the report (paper, ink borders, hard shadows).
$resources = @'
  <Window.Resources>
    <DropShadowEffect x:Key="Hard" Color="#161513" ShadowDepth="5" Direction="315" BlurRadius="0" Opacity="1"/>
    <DropShadowEffect x:Key="HardSm" Color="#161513" ShadowDepth="3" Direction="315" BlurRadius="0" Opacity="1"/>
    <Style TargetType="Button">
      <Setter Property="Background" Value="#FFFDF8"/>
      <Setter Property="BorderBrush" Value="#161513"/>
      <Setter Property="BorderThickness" Value="3"/>
      <Setter Property="Padding" Value="14,6"/>
      <Setter Property="Margin" Value="0,0,12,0"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Effect" Value="{StaticResource HardSm}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#FBE7B5"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.45"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#F2B632"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="BorderBrush" Value="#161513"/>
      <Setter Property="BorderThickness" Value="2"/>
      <Setter Property="Padding" Value="6,4"/>
      <Setter Property="Background" Value="#FFFDF8"/>
    </Style>
    <Style TargetType="PasswordBox">
      <Setter Property="BorderBrush" Value="#161513"/>
      <Setter Property="BorderThickness" Value="2"/>
      <Setter Property="Padding" Value="6,4"/>
      <Setter Property="Background" Value="#FFFDF8"/>
    </Style>
    <Style TargetType="ComboBox">
      <Setter Property="BorderBrush" Value="#161513"/>
      <Setter Property="BorderThickness" Value="2"/>
      <Setter Property="Padding" Value="6,4"/>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Margin" Value="0,4,18,4"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>
    <Style TargetType="RadioButton">
      <Setter Property="Margin" Value="0,4,18,4"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>
    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="#FFFDF8"/>
      <Setter Property="BorderBrush" Value="#161513"/>
      <Setter Property="BorderThickness" Value="3"/>
      <Setter Property="Padding" Value="18"/>
      <Setter Property="Margin" Value="0,0,8,18"/>
      <Setter Property="Effect" Value="{StaticResource Hard}"/>
    </Style>
    <Style x:Key="H2" TargetType="TextBlock">
      <Setter Property="FontFamily" Value="Bahnschrift, Segoe UI"/>
      <Setter Property="FontSize" Value="20"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Margin" Value="0,0,0,10"/>
    </Style>
    <Style x:Key="H3" TargetType="TextBlock">
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Margin" Value="0,12,0,4"/>
    </Style>
    <Style x:Key="Muted" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#5F5A51"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="Margin" Value="0,2,0,8"/>
    </Style>
    <Style x:Key="Label" TargetType="TextBlock">
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="Margin" Value="0,4,12,4"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
  </Window.Resources>
'@
$windowOpen = '<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"'

# ---------------- The main window: the form on the left, the outputs and the log on the right.
[xml]$xaml = $windowOpen + @'
        Title="HostBadger" Width="1360" Height="900" MinWidth="1060" MinHeight="660"
        Background="#F3EFE6" FontFamily="Segoe UI" FontSize="14" Foreground="#161513" WindowStartupLocation="CenterScreen">
'@ + $resources + @'
  <Grid Margin="22">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0" Style="{StaticResource Card}" Padding="18,10">
      <DockPanel LastChildFill="False">
        <StackPanel DockPanel.Dock="Left" Orientation="Horizontal">
          <TextBlock x:Name="LogoText" FontFamily="Cascadia Mono, Consolas" FontSize="9" LineHeight="10" LineStackingStrategy="BlockLineHeight" VerticalAlignment="Center" Margin="0,0,16,0"/>
          <StackPanel VerticalAlignment="Center">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="HostBadger" FontFamily="Bahnschrift, Segoe UI" FontSize="30" FontWeight="Bold"/>
              <TextBlock x:Name="VersionText" Margin="12,0,0,4" VerticalAlignment="Bottom" FontFamily="Cascadia Mono, Consolas" Foreground="#5F5A51"/>
            </StackPanel>
            <TextBlock Text="Windows host hardening: read-only snapshots, offline analysis" Foreground="#5F5A51"/>
          </StackPanel>
        </StackPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Vertical" HorizontalAlignment="Right" VerticalAlignment="Center">
          <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
            <Border x:Name="AdminPill" BorderBrush="#161513" BorderThickness="2" Padding="10,3" Margin="0,0,12,0" VerticalAlignment="Center">
              <TextBlock x:Name="AdminText" FontWeight="Bold"/>
            </Border>
            <Button x:Name="ElevateBtn" Content="Restart as administrator"/>
            <Button x:Name="SettingsBtn" Content="Settings"/>
            <Button x:Name="SafetyBtn" Content="Safety review" ToolTip="Test-HostBadgerSafety.ps1 reads the scripts (it runs nothing) and lists every command they use, where they write and where they may connect."/>
            <Button x:Name="UpdateCheckBtn" Content="Check for updates" Margin="0"/>
          </StackPanel>
          <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
            <TextBlock x:Name="UpdateText" VerticalAlignment="Center" Foreground="#5F5A51" Margin="0,0,12,0" TextWrapping="Wrap" MaxWidth="520"/>
            <Button x:Name="UpdateBtn" Content="Update" Style="{StaticResource Primary}" Margin="0" Visibility="Collapsed"/>
          </StackPanel>
        </StackPanel>
      </DockPanel>
    </Border>

    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*" MinWidth="560"/>
        <ColumnDefinition Width="10"/>
        <ColumnDefinition Width="440" MinWidth="300"/>
      </Grid.ColumnDefinitions>

      <!-- Left: the form and its actions -->
      <Grid Grid.Column="0">
        <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
        <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="0,0,8,0">
          <StackPanel>
            <Border Style="{StaticResource Card}">
              <StackPanel>
                <TextBlock Text="What to analyze" Style="{StaticResource H2}"/>
                <RadioButton x:Name="SrcMachine" GroupName="Src" FontWeight="SemiBold" Content="This machine: collect a read-only snapshot now, then analyze it"/>
                <StackPanel x:Name="MachinePanel" Margin="26,2,0,10">
                  <TextBlock x:Name="CollectNote" Style="{StaticResource Muted}"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="164"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                    <TextBlock Text="Save the snapshot in" Style="{StaticResource Label}"/>
                    <TextBox x:Name="CollectDirBox" Grid.Column="1" Margin="0,4"/>
                    <Button x:Name="CollectDirBtn" Grid.Column="2" Content="Folder..." Margin="12,4,0,4"/>
                  </Grid>
                  <CheckBox x:Name="SkipAclChk" Content="Skip file permissions (faster, fewer checks)"/>
                  <CheckBox x:Name="UpdatesChk"/>
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="Encryption" Style="{StaticResource Label}"/>
                    <RadioButton x:Name="EncNone" Content="None" IsChecked="True"/>
                    <RadioButton x:Name="EncPass" Content="Password" Margin="0,4,8,4"/>
                    <PasswordBox x:Name="EncPassBox" Width="160" Margin="0,4,18,4"/>
                    <RadioButton x:Name="EncCert" Content="Certificate (.cer or thumbprint)" Margin="0,4,8,4"/>
                    <TextBox x:Name="EncCertBox" Width="200" Margin="0,4"/>
                  </StackPanel>
                </StackPanel>
                <RadioButton x:Name="SrcSnap" GroupName="Src" FontWeight="SemiBold" Content="Snapshots already collected: a file, or a folder with several hosts"/>
                <StackPanel x:Name="SnapPanel" Margin="26,2,0,0">
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="164"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                    <Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
                    <TextBlock Text="Snapshot file or folder" Style="{StaticResource Label}"/>
                    <TextBox x:Name="SnapshotBox" Grid.Column="1" Margin="0,4"/>
                    <StackPanel Grid.Column="2" Orientation="Horizontal" Margin="12,4,0,4">
                      <Button x:Name="SnapFileBtn" Content="File..."/>
                      <Button x:Name="SnapFolderBtn" Content="Folder..." Margin="0"/>
                    </StackPanel>
                    <TextBlock x:Name="SnapshotNote" Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="2" Style="{StaticResource Muted}"/>
                    <TextBlock Grid.Row="2" Text="Password (.hbx)" Style="{StaticResource Label}"/>
                    <PasswordBox x:Name="SnapPassBox" Grid.Row="2" Grid.Column="1" Margin="0,4"/>
                    <TextBlock Grid.Row="2" Grid.Column="2" Text="only for encrypted snapshots" Style="{StaticResource Muted}" Margin="12,4,0,4" VerticalAlignment="Center"/>
                  </Grid>
                </StackPanel>
              </StackPanel>
            </Border>

            <Border Style="{StaticResource Card}">
              <StackPanel>
                <TextBlock Text="Report" Style="{StaticResource H2}"/>
                <Grid>
                  <Grid.ColumnDefinitions><ColumnDefinition Width="190"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                  <TextBlock Text="Save the new report as" Style="{StaticResource Label}"/>
                  <TextBox x:Name="ReportBox" Grid.Column="1" Margin="0,4"/>
                </Grid>
                <WrapPanel Margin="0,10,0,0">
                  <CheckBox x:Name="StigChk" Content="Include the DISA STIG rules" IsChecked="True"/>
                  <CheckBox x:Name="ShowStigChk" Content="Show the DISA STIG findings" IsChecked="True"/>
                  <CheckBox x:Name="ShowCisChk" Content="Show the CIS-based findings" IsChecked="True"/>
                  <CheckBox x:Name="JsonlChk" Content="JSON Lines for a SIEM"/>
                  <CheckBox x:Name="PerHostChk" Content="One report per host (folders with several hosts)" IsChecked="True"/>
                </WrapPanel>
                <CheckBox x:Name="AcnChk" Content="NIS2: add the ACN basic measures (Italy only: Determinazione 379907/2025, D.Lgs. 138/2024)"/>
              </StackPanel>
            </Border>

            <Border Style="{StaticResource Card}">
              <StackPanel>
                <TextBlock Text="Catalogs" Style="{StaticResource H2}"/>
                <TextBlock Style="{StaticResource Muted}" Text="HostBadger ships a copy of the drivers and extensions lists and a software lifecycle table, used offline. A download is one or a few HTTPS GETs to the address shown (nothing about the hosts is sent); it is kept next to the report and offered to the next analysis."/>
                <Grid x:Name="CatalogGrid">
                  <Grid.ColumnDefinitions><ColumnDefinition Width="230"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                </Grid>
              </StackPanel>
            </Border>

            <Border Style="{StaticResource Card}">
              <StackPanel>
                <TextBlock Text="Fix" Style="{StaticResource H2}"/>
                <CheckBox x:Name="RemChk" Content="Fix what the analysis finds" FontWeight="SemiBold"/>
                <TextBlock x:Name="RemWarn" TextWrapping="Wrap" Margin="0,4,0,0"/>
                <StackPanel x:Name="RemPanel" Margin="0,4,0,0">
                  <TextBlock Text="What the scripts change" Style="{StaticResource H3}" Margin="0,4,0,4"/>
                  <StackPanel x:Name="ProfilePanel"/>
                  <TextBlock Text="Also" Style="{StaticResource H3}"/>
                  <CheckBox x:Name="DebloatChk" Content="Debloat: preinstalled Store apps (workstations), unused consumer services and Windows components (Xbox, Fax, Steps Recorder...). Strict includes it"/>
                  <CheckBox x:Name="PrivacyChk" Content="Disable telemetry: the privacy and telemetry settings of every level (Strict includes them)"/>
                  <TextBlock x:Name="RemOutText" Style="{StaticResource Muted}" Margin="0,8,0,0"/>
                </StackPanel>
              </StackPanel>
            </Border>

            <Border Style="{StaticResource Card}">
              <StackPanel>
                <TextBlock Text="Your organization" Style="{StaticResource H2}"/>
                <TextBlock Style="{StaticResource Muted}" Text="Optional. Lists are comma separated."/>
                <Grid>
                  <Grid.ColumnDefinitions><ColumnDefinition Width="230"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                  <Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
                  <TextBlock Text="Allowed administrators" Style="{StaticResource Label}"/>
                  <TextBox x:Name="AdminsBox" Grid.Column="1" Margin="0,4"/>
                  <TextBlock Grid.Row="1" Text="Expected EDR" Style="{StaticResource Label}"/>
                  <TextBox x:Name="EdrBox" Grid.Row="1" Grid.Column="1" Margin="0,4"/>
                  <TextBlock Grid.Row="2" Text="Approved remote tools" Style="{StaticResource Label}"/>
                  <TextBox x:Name="RatBox" Grid.Row="2" Grid.Column="1" Margin="0,4"/>
                  <TextBlock Grid.Row="3" Text="Approved browser extensions" Style="{StaticResource Label}"/>
                  <TextBox x:Name="ExtBox" Grid.Row="3" Grid.Column="1" Margin="0,4"/>
                  <TextBlock Grid.Row="4" Text="Exceptions file" Style="{StaticResource Label}"/>
                  <TextBox x:Name="ExceptionsBox" Grid.Row="4" Grid.Column="1" Margin="0,4"/>
                  <TextBlock Grid.Row="5" Text="Policy file" Style="{StaticResource Label}"/>
                  <TextBox x:Name="PolicyBox" Grid.Row="5" Grid.Column="1" Margin="0,4"/>
                  <TextBlock Grid.Row="6" Text="Compare with (earlier CSV)" Style="{StaticResource Label}"/>
                  <TextBox x:Name="CompareBox" Grid.Row="6" Grid.Column="1" Margin="0,4"/>
                </Grid>
              </StackPanel>
            </Border>
          </StackPanel>
        </ScrollViewer>

        <!-- Actions -->
        <Border Grid.Row="1" Style="{StaticResource Card}" Padding="14,12" Margin="0,0,8,0">
          <StackPanel>
            <DockPanel LastChildFill="False">
              <StackPanel DockPanel.Dock="Left" Orientation="Horizontal">
                <Button x:Name="RunBtn" Content="Analyze" Style="{StaticResource Primary}"/>
                <Button x:Name="OpenBtn" Content="Open the last report" IsEnabled="False" Margin="0"/>
              </StackPanel>
              <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
                <Button x:Name="AiDryBtn" Content="AI: dry run"/>
                <Button x:Name="AiSendBtn" Content="AI: send to Gemini" Margin="0"/>
              </StackPanel>
            </DockPanel>
            <DockPanel Margin="0,8,0,0">
              <Button x:Name="AiPickBtn" DockPanel.Dock="Right" Content="Other report..." Margin="8,0,0,0" VerticalAlignment="Center"/>
              <TextBlock x:Name="AiTargetText" Foreground="#5F5A51" VerticalAlignment="Center" TextWrapping="Wrap"/>
            </DockPanel>
            <DockPanel LastChildFill="False" Margin="0,10,0,0">
              <StackPanel DockPanel.Dock="Left" Orientation="Horizontal" VerticalAlignment="Center">
                <ProgressBar x:Name="Busy" Width="120" Height="10" IsIndeterminate="False" Margin="0,0,10,0" Foreground="#E2372A" Background="#E8E2D4" BorderBrush="#161513"/>
                <TextBlock x:Name="StatusText" Foreground="#5F5A51"/>
              </StackPanel>
              <TextBlock x:Name="AiInfoText" DockPanel.Dock="Right" Foreground="#5F5A51" VerticalAlignment="Center"/>
            </DockPanel>
          </StackPanel>
        </Border>
      </Grid>

      <GridSplitter Grid.Column="1" Width="10" HorizontalAlignment="Stretch" Background="Transparent" Cursor="SizeWE"/>

      <!-- Right: what the last runs wrote, then the log -->
      <Grid Grid.Column="2">
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
        <Border Style="{StaticResource Card}" Padding="16,12" Margin="0,0,6,18">
          <StackPanel>
            <TextBlock Text="Outputs" Style="{StaticResource H2}" Margin="0,0,0,6"/>
            <StackPanel x:Name="OutputsPanel"/>
          </StackPanel>
        </Border>
        <Border Grid.Row="1" BorderBrush="#161513" BorderThickness="3" Background="#161513" Margin="0,0,6,0">
          <Grid>
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <TextBlock Text="LOG" Foreground="#F2B632" FontWeight="Bold" FontFamily="Cascadia Mono, Consolas" Margin="10,6,10,0"/>
            <TextBox x:Name="LogBox" Grid.Row="1" IsReadOnly="True" Background="#161513" Foreground="#F3EFE6" BorderThickness="0" FontFamily="Cascadia Mono, Consolas" FontSize="12"
                     VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" TextWrapping="Wrap" Padding="10,6,10,10"/>
          </Grid>
        </Border>
      </Grid>
    </Grid>
  </Grid>
</Window>
'@

# ---------------- The Settings window: what stays the same at every run (menu 8 of the guided menu).
[xml]$settingsXaml = $windowOpen + @'
        Title="HostBadger settings" Width="820" Height="780" MinWidth="700" MinHeight="520"
        Background="#F3EFE6" FontFamily="Segoe UI" FontSize="14" Foreground="#161513" WindowStartupLocation="CenterOwner">
'@ + $resources + @'
  <Grid Margin="22">
    <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="0,0,8,0">
      <StackPanel>
        <Border Style="{StaticResource Card}">
          <StackPanel>
            <TextBlock Text="Folders" Style="{StaticResource H2}"/>
            <Grid>
              <Grid.ColumnDefinitions><ColumnDefinition Width="170"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
              <Grid.RowDefinitions><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
              <TextBlock Text="Snapshots" Style="{StaticResource Label}"/>
              <TextBox x:Name="SetSnapDir" Grid.Column="1" Margin="0,4"/>
              <Button x:Name="SetSnapDirBtn" Grid.Column="2" Content="Folder..." Margin="12,4,0,4"/>
              <TextBlock Grid.Row="1" Text="Reports" Style="{StaticResource Label}"/>
              <TextBox x:Name="SetRepDir" Grid.Row="1" Grid.Column="1" Margin="0,4"/>
              <Button x:Name="SetRepDirBtn" Grid.Row="1" Grid.Column="2" Content="Folder..." Margin="12,4,0,4"/>
            </Grid>
          </StackPanel>
        </Border>

        <Border Style="{StaticResource Card}">
          <StackPanel>
            <TextBlock Text="AI summary (Gemini)" Style="{StaticResource H2}"/>
            <Grid>
              <Grid.ColumnDefinitions><ColumnDefinition Width="170"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
              <TextBlock Text="API key" Style="{StaticResource Label}"/>
              <PasswordBox x:Name="SetGeminiKey" Grid.Column="1" Margin="0,4"/>
              <TextBlock x:Name="SetGeminiState" Grid.Row="1" Grid.Column="1" Style="{StaticResource Muted}"/>
              <TextBlock Grid.Row="2" Text="Model" Style="{StaticResource Label}"/>
              <ComboBox x:Name="SetModel" Grid.Row="2" Grid.Column="1" Margin="0,4" IsEditable="True"/>
              <TextBlock Grid.Row="3" Text="Attempts" Style="{StaticResource Label}"/>
              <StackPanel Grid.Row="3" Grid.Column="1" Orientation="Horizontal">
                <ComboBox x:Name="SetAttempts" Width="80" Margin="0,4"/>
                <TextBlock Text="tries on a timeout or a busy server (429, 5xx); 0 keeps trying" Style="{StaticResource Muted}" Margin="12,4,0,4" VerticalAlignment="Center"/>
              </StackPanel>
              <CheckBox x:Name="SetAiStig" Grid.Row="4" Grid.Column="1" Content="Also send the DISA STIG findings (a very large prompt may time out)"/>
            </Grid>
            <CheckBox x:Name="SetGeminiRemember" Content="Remember the key for my Windows account (user environment variable GEMINI__API__KEY)"/>
            <TextBlock Style="{StaticResource Muted}" Text="Without it the key is kept for this window only. A key is never written in the settings file."/>
          </StackPanel>
        </Border>

        <Border Style="{StaticResource Card}">
          <StackPanel>
            <TextBlock Text="NVD (CVEs and EPSS)" Style="{StaticResource H2}"/>
            <Grid>
              <Grid.ColumnDefinitions><ColumnDefinition Width="170"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <Grid.RowDefinitions><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
              <TextBlock Text="NVD API key" Style="{StaticResource Label}"/>
              <PasswordBox x:Name="SetNvdKey" Grid.Column="1" Margin="0,4"/>
              <TextBlock x:Name="SetNvdState" Grid.Row="1" Grid.Column="1" Style="{StaticResource Muted}"/>
            </Grid>
            <CheckBox x:Name="SetNvdRemember" Content="Remember the key for my Windows account (user environment variable NVD__API__KEY)"/>
            <TextBlock Style="{StaticResource Muted}" Text="Optional: the CVE download takes about 2.5 minutes without it, much less with it. It is sent only to services.nvd.nist.gov, as a header."/>
          </StackPanel>
        </Border>

        <Border Style="{StaticResource Card}">
          <StackPanel>
            <TextBlock Text="Catalogs" Style="{StaticResource H2}"/>
            <TextBlock Style="{StaticResource Muted}" Text="What the analysis form proposes for each catalog."/>
            <Grid x:Name="SetCatalogGrid">
              <Grid.ColumnDefinitions><ColumnDefinition Width="230"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            </Grid>
          </StackPanel>
        </Border>

        <Border Style="{StaticResource Card}">
          <StackPanel>
            <TextBlock Text="Collection" Style="{StaticResource H2}"/>
            <TextBlock Text="Encryption proposed for a new snapshot" Style="{StaticResource Label}"/>
            <StackPanel Orientation="Horizontal">
              <RadioButton x:Name="SetEncAsk" Content="Ask (guided menu)" IsChecked="True"/>
              <RadioButton x:Name="SetEncNone" Content="None"/>
              <RadioButton x:Name="SetEncPass" Content="Password (typed each time)"/>
              <RadioButton x:Name="SetEncCert" Content="Certificate" Margin="0,4,8,4"/>
              <TextBox x:Name="SetCert" Width="240" Margin="0,4"/>
            </StackPanel>
          </StackPanel>
        </Border>
      </StackPanel>
    </ScrollViewer>
    <DockPanel Grid.Row="1" LastChildFill="False" Margin="0,4,0,0">
      <TextBlock x:Name="SetPathText" DockPanel.Dock="Left" Foreground="#5F5A51" VerticalAlignment="Center" TextWrapping="Wrap" MaxWidth="460"/>
      <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
        <Button x:Name="SetSaveBtn" Content="Save" Style="{StaticResource Primary}"/>
        <Button x:Name="SetCancelBtn" Content="Cancel" Margin="0"/>
      </StackPanel>
    </DockPanel>
  </Grid>
</Window>
'@

function New-BadgerIcon {
    # The window and taskbar icon: a badger head drawn as vectors (the ASCII logo cannot be read at 32 pixels).
    param([int]$Size = 64)
    $d = [Windows.Markup.XamlReader]::Parse(@'
<DrawingGroup xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
  <GeometryDrawing Brush="#23211C" Geometry="M6,14 A8,8 0 1 1 22,8 Z M58,14 A8,8 0 1 0 42,8 Z"/>
  <GeometryDrawing Brush="#F4F1EA" Geometry="M32,6 C50,6 58,22 56,36 C54,50 44,60 32,60 C20,60 10,50 8,36 C6,22 14,6 32,6 Z">
    <GeometryDrawing.Pen><Pen Brush="#23211C" Thickness="3"/></GeometryDrawing.Pen>
  </GeometryDrawing>
  <GeometryDrawing Brush="#23211C" Geometry="M22,8 C15,20 15,36 24,50 L31,47 C26,36 26,22 29,7 Z M42,8 C49,20 49,36 40,50 L33,47 C38,36 38,22 35,7 Z"/>
  <GeometryDrawing Brush="#F4F1EA" Geometry="M21,33 A2.6,2.6 0 1 1 26.2,33 A2.6,2.6 0 1 1 21,33 Z M37.8,33 A2.6,2.6 0 1 1 43,33 A2.6,2.6 0 1 1 37.8,33 Z"/>
  <GeometryDrawing Brush="#23211C" Geometry="M26,53 C26,49 38,49 38,53 C38,57 26,57 26,53 Z"/>
</DrawingGroup>
'@)
    $v = New-Object System.Windows.Media.DrawingVisual
    $dc = $v.RenderOpen()
    $dc.PushTransform((New-Object System.Windows.Media.ScaleTransform ($Size / 64), ($Size / 64)))
    $dc.DrawDrawing($d); $dc.Close()
    $bmp = New-Object System.Windows.Media.Imaging.RenderTargetBitmap $Size, $Size, 96, 96, ([System.Windows.Media.PixelFormats]::Pbgra32)
    $bmp.Render($v); $bmp.Freeze()
    return $bmp
}
$script:BadgerIcon = New-BadgerIcon

function New-XamlWindow {
    # A window and its named controls.
    param([xml]$Xml)
    $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $Xml))
    $w.Icon = $script:BadgerIcon
    $named = @{}
    foreach ($n in $Xml.SelectNodes('//*[@*[local-name()="Name"]]')) { $name = $n.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml'); if ($name) { $named[$name] = $w.FindName($name) } }
    return @{ Window = $w; Ui = $named }
}
$main = New-XamlWindow $xaml
$window = $main.Window
$ui = $main.Ui

# ---------------- Helpers.
function Add-Log {
    param([string]$Text)
    $ui.LogBox.AppendText("$Text`r`n")
    $ui.LogBox.ScrollToEnd()
}
function Split-List { param([string]$Text) return @("$Text" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
function Get-Stamp { return (Get-Date).ToString('yyyyMMdd_HHmmss') }
function Get-FullPath { param([string]$Path) if (-not $Path) { return '' }; if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }; return (Join-Path $PWD.ProviderPath $Path) }
function Get-PlainSecret {
    # A password box as text, for the parameters that take text (the collector's -EncryptPassword, the keys).
    param($Box)
    if (-not $Box.SecurePassword -or $Box.SecurePassword.Length -eq 0) { return '' }
    return (New-Object System.Net.NetworkCredential('', $Box.SecurePassword)).Password
}
function New-Brush { param([string]$Hex) return (New-Object System.Windows.Media.BrushConverter).ConvertFromString($Hex) }
function Find-KeptCatalog {
    # The newest kept copy of a catalog next to the report or in .\output, as the guided menu does.
    param([string]$Suffix, [string]$Report)
    $full = Get-FullPath $Report
    $dirs = @((Split-Path -Parent $full), (Join-Path $PWD.ProviderPath 'output')) | Sort-Object -Unique
    $hits = @(foreach ($d in $dirs) { if ($d -and (Test-Path -LiteralPath $d -PathType Container)) { Get-ChildItem -LiteralPath $d -File -Filter "*_$Suffix.json" -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 } } })
    if ($hits.Count -eq 0) { return }
    return ($hits | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
}
function Find-LatestSnapshot {
    # The newest snapshot file in a folder (the collector writes hostsnapshot_<HOST>_<time>.zip/.json/.hbx).
    param([string]$Dir)
    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir -PathType Container)) { return }
    $f = @(Get-ChildItem -LiteralPath $Dir -File -Filter 'hostsnapshot_*' -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.zip', '.json', '.hbx' } | Sort-Object LastWriteTimeUtc -Descending)
    if ($f.Count) { return $f[0] }
}
function Find-LatestReport {
    # The newest fleet report in a folder: an .html with the .csv of the same name (per-host reports have none).
    param([string]$Dir)
    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir -PathType Container)) { return }
    $f = @(Get-ChildItem -LiteralPath $Dir -File -Filter '*.html' -ErrorAction SilentlyContinue | Where-Object { Test-Path -LiteralPath ($_.FullName -replace '\.html$', '.csv') } | Sort-Object LastWriteTimeUtc -Descending)
    if ($f.Count) { return $f[0] }
}
function Get-WuSource {
    $wuSource = 'Microsoft Update (HTTPS to *.update.microsoft.com)'
    try {
        $wuPol = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction Stop
        $wuAu = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
        if ($wuPol.WUServer -and $wuAu -and $wuAu.UseWUServer -eq 1) { $wuSource = "the WSUS server $($wuPol.WUServer)" }
    }
    catch { }
    return $wuSource
}

# ---------------- Background work: one runspace for the window, so the analysis kept for the AI step
# (-AiLater) is still there for -AiContinue. Output is read by a timer on the window's thread.
$script:Rs = [runspacefactory]::CreateRunspace()
$script:Rs.ApartmentState = 'STA'
$script:Rs.ThreadOptions = 'ReuseThread'
$script:Rs.Open()
$script:Task = $null
$script:LastReport = ''
$script:LastSnapshot = ''
$script:Kept = $false
$script:ApplyAfter = $false

function Set-Busy {
    param([bool]$On, [string]$Text = '')
    $ui.Busy.IsIndeterminate = $On
    $ui.StatusText.Text = $Text
    foreach ($b in 'RunBtn', 'UpdateCheckBtn', 'UpdateBtn', 'ElevateBtn', 'SettingsBtn', 'SafetyBtn') { $ui[$b].IsEnabled = -not $On }
    foreach ($b in 'AiDryBtn', 'AiSendBtn', 'AiPickBtn') { $ui[$b].IsEnabled = -not $On }
    if (-not $On) { Update-AiTarget }
}

function Start-GuiTask {
    # Work: a script block run in the background runspace (as text, so it belongs to that runspace).
    # Its text output goes to the log; objects with a Kind go to Done.
    param([string]$Label, [scriptblock]$Work, [object[]]$Arguments, [scriptblock]$Done)
    if ($script:Task) { return }
    $ps = [powershell]::Create()
    $ps.Runspace = $script:Rs
    [void]$ps.AddScript($Work.ToString())
    foreach ($a in $Arguments) { [void]$ps.AddArgument($a) }
    $in = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
    $in.Complete()
    $out = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
    $handle = $ps.BeginInvoke($in, $out)
    $script:Task = @{ Ps = $ps; Handle = $handle; Out = $out; Seen = 0; ErrSeen = 0; Done = $Done; Results = (New-Object System.Collections.Generic.List[object]); Lines = (New-Object System.Collections.Generic.List[string]) }
    Add-Log ''
    Add-Log "--- $Label ---"
    Set-Busy $true $Label
    $script:Timer.Start()
}

function Read-GuiTask {
    $t = $script:Task
    if (-not $t) { return }
    while ($t.Seen -lt $t.Out.Count) {
        $o = $t.Out[$t.Seen]; $t.Seen++
        if ($o -and $o.PSObject.Properties['Kind']) { $t.Results.Add($o) } else { $line = "$o"; $t.Lines.Add($line); Add-Log $line }
    }
    $errs = $t.Ps.Streams.Error
    while ($t.ErrSeen -lt $errs.Count) { Add-Log "ERROR: $($errs[$t.ErrSeen])"; $t.ErrSeen++ }
    if (-not $t.Handle.IsCompleted) { return }
    $script:Timer.Stop()
    try { [void]$t.Ps.EndInvoke($t.Handle) } catch { Add-Log "Stopped: $($_.Exception.Message)" }
    while ($t.Seen -lt $t.Out.Count) { $o = $t.Out[$t.Seen]; $t.Seen++; if ($o -and $o.PSObject.Properties['Kind']) { $t.Results.Add($o) } else { $t.Lines.Add("$o"); Add-Log "$o" } }
    $t.Ps.Dispose()
    $script:Task = $null
    Set-Busy $false 'Ready'
    if ($t.Done) { & $t.Done $t }
}
$script:Timer = New-Object System.Windows.Threading.DispatcherTimer
$script:Timer.Interval = [TimeSpan]::FromMilliseconds(250)
$script:Timer.Add_Tick({ Read-GuiTask })

# Runs a HostBadger script with its parameters; what it prints comes back as text.
$script:RunScript = {
    param([string]$Path, [hashtable]$Params)
    $env:HOSTBADGER_NO_SPINNER = '1'
    & $Path @Params *>&1 | ForEach-Object { "$_" }
}

# ---------------- Outputs: links to what the last analysis and collection wrote.
function Add-OutputLink {
    param([string]$Label, [string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Margin = '0,2,0,2'; $tb.TextWrapping = 'Wrap'
    $lbl = New-Object System.Windows.Documents.Run ("$Label  ")
    $lbl.FontWeight = 'SemiBold'
    $link = New-Object System.Windows.Documents.Hyperlink (New-Object System.Windows.Documents.Run (Split-Path -Leaf $Path))
    $link.Tag = $Path; $link.Foreground = New-Brush '#8A5A00'; $link.ToolTip = $Path
    $link.Add_Click({ param($s) try { Invoke-Item -LiteralPath $s.Tag } catch { Add-Log "Not opened: $($_.Exception.Message)" } })
    $tb.Inlines.Add($lbl); $tb.Inlines.Add($link)
    [void]$ui.OutputsPanel.Children.Add($tb)
}
function Update-Outputs {
    $ui.OutputsPanel.Children.Clear()
    $r = $script:LastReport
    if ($r -and (Test-Path -LiteralPath $r)) {
        $base = $r -replace '\.html?$', ''
        Add-OutputLink 'Report' $r
        foreach ($p in @(Get-ChildItem -LiteralPath (Split-Path -Parent $r) -File -Filter "$(Split-Path -Leaf $base)_*.html" -ErrorAction SilentlyContinue | Sort-Object Name)) { Add-OutputLink "Host $($p.BaseName.Substring((Split-Path -Leaf $base).Length + 1))" $p.FullName }
        Add-OutputLink 'Run log' "$base.log"
        Add-OutputLink 'CSV' "$base.csv"
        Add-OutputLink 'JSON Lines' "$base.jsonl"
        Add-OutputLink 'Fix scripts' "$($base)_fixes"
        Add-OutputLink 'Rollback file' "$($base)_fixes\rollback.json"
        Add-OutputLink 'AI prompt' "$($base)_ai_prompt.txt"
        Add-OutputLink 'AI answer' "$($base)_ai_response.json"
        Add-OutputLink 'Report folder' (Split-Path -Parent $r)
    }
    if ($script:LastSnapshot) { Add-OutputLink 'Snapshot' $script:LastSnapshot; Add-OutputLink 'Snapshot folder' (Split-Path -Parent $script:LastSnapshot) }
    Add-OutputLink 'Settings' $script:SettingsPath
    if ($ui.OutputsPanel.Children.Count -eq 0) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = 'Nothing yet: the report, its log and the other files of a run appear here.'; $tb.Foreground = New-Brush '#5F5A51'; $tb.TextWrapping = 'Wrap'
        [void]$ui.OutputsPanel.Children.Add($tb)
    }
    $ui.OpenBtn.IsEnabled = [bool]($r -and (Test-Path -LiteralPath $r))
}

# ---------------- Settings: the guided menu's global settings fill the form.
function Read-Settings {
    if (-not (Test-Path -LiteralPath $script:SettingsPath)) { return $null }
    try { return ([System.IO.File]::ReadAllText($script:SettingsPath) | ConvertFrom-Json) } catch { return $null }
}
function Write-Settings {
    # Changes some keys of the settings file, keeping the others (the guided menu's included).
    param([hashtable]$Values)
    $s = [ordered]@{}
    $old = Read-Settings
    if ($old) { foreach ($p in $old.PSObject.Properties) { $s[$p.Name] = $p.Value } }
    if (-not $s.Contains('version')) { $s['version'] = 1 }
    foreach ($k in $Values.Keys) { $s[$k] = $Values[$k] }
    $s['savedUtc'] = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC'
    $dir = Split-Path -Parent $script:SettingsPath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($script:SettingsPath, (ConvertTo-Json -InputObject $s), (New-Object System.Text.UTF8Encoding($false)))
}
function Get-SnapshotDir { $s = Read-Settings; if ($s -and $s.SnapshotDir) { return (Get-FullPath "$($s.SnapshotDir)") }; return (Join-Path $PWD.ProviderPath 'snapshots') }
function Get-ReportDir { $s = Read-Settings; if ($s -and $s.ReportDir) { return (Get-FullPath "$($s.ReportDir)") }; return (Join-Path $PWD.ProviderPath 'output') }
function Update-AiTarget {
    # Which report the AI buttons add their summary to: the last one, or one chosen from an earlier run.
    if (-not $script:LastReport -or -not (Test-Path -LiteralPath $script:LastReport)) { $ui.AiTargetText.Text = 'AI summary: no report yet. Analyze first, or choose an earlier report.'; return }
    $name = Split-Path -Leaf $script:LastReport
    if ($script:Kept) { $ui.AiTargetText.Text = "AI summary goes into $name (the analysis is in memory)."; return }
    $ui.AiTargetText.Text = "AI summary goes into $name (earlier report: the snapshot above is analyzed again, then the report is rewritten)."
}

function Update-AiInfo {
    $s = Read-Settings
    $model = if ($s -and $s.Model) { "$($s.Model)" } else { $script:DefaultModel }
    $att = if ($s -and "$($s.AiMaxAttempts)") { "$($s.AiMaxAttempts)" } else { '3' }
    $key = if ($env:GEMINI_API_KEY) { 'key set' } else { 'no key (Settings)' }
    $ui.AiInfoText.Text = "Gemini: $model, $(if ($att -eq '0') { 'tries until it works' } else { "$att attempts" }), $key"
}

$script:CatalogBoxes = @{}
function Select-LatestSnapshot {
    # The analysis form always proposes the newest snapshot of the snapshot folder.
    param([string]$Dir)
    $f = Find-LatestSnapshot $Dir
    if ($f) { $ui.SnapshotBox.Text = $f.FullName; $ui.SnapshotNote.Text = "The newest snapshot in $Dir ($($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))). Folder... analyzes every host of a folder (the newest snapshot of each)." }
    else { $ui.SnapshotNote.Text = "No snapshot in $Dir yet: collect this machine, or choose a file or a folder." }
}
function Initialize-Form {
    $s = Read-Settings
    $ui.LogoText.Text = $script:Logo
    $ui.VersionText.Text = "v$($script:LocalVersion)"
    $ui.AdminText.Text = if ($script:IsAdmin) { 'administrator' } else { 'not administrator' }
    $ui.AdminPill.Background = if ($script:IsAdmin) { New-Brush '#84CC5F' } else { New-Brush '#FBE7B5' }
    $ui.ElevateBtn.Visibility = if ($script:IsAdmin) { 'Collapsed' } else { 'Visible' }
    $ui.CollectNote.Text = "Read only: nothing on this machine changes. $(if ($script:IsAdmin) { 'Running as administrator: full coverage.' } else { 'Not administrator: some checks will be listed as not evaluated (Restart as administrator for full coverage).' }) The snapshot describes this machine: keep it like any other sensitive file."
    $ui.UpdatesChk.Content = "Search missing updates (the Windows Update service contacts $(Get-WuSource))"
    $snapDir = Get-SnapshotDir
    $ui.CollectDirBox.Text = $snapDir
    Select-LatestSnapshot $snapDir
    if ($s -and "$($s.GuiSource)" -eq 'snapshots') { $ui.SrcSnap.IsChecked = $true } else { $ui.SrcMachine.IsChecked = $true }
    $repDir = Get-ReportDir
    $ui.ReportBox.Text = Join-Path $repDir "hostbadger_$(Get-Stamp).html"
    $last = Find-LatestReport $repDir
    if ($last) { $script:LastReport = $last.FullName }
    if ($s) {
        $ui.SkipAclChk.IsChecked = [bool]$s.SkipAcl; $ui.UpdatesChk.IsChecked = [bool]$s.CheckUpdates
        $ui.PerHostChk.IsChecked = [bool]$s.PerHost; $ui.StigChk.IsChecked = -not [bool]$s.SkipStig
        $ui.ShowCisChk.IsChecked = -not [bool]$s.HideCis; $ui.ShowStigChk.IsChecked = -not [bool]$s.HideStig
        $ui.AcnChk.IsChecked = [bool]$s.Nis2Acn; $ui.JsonlChk.IsChecked = [bool]$s.Jsonl; $ui.RemChk.IsChecked = [bool]$s.Remediation
        $ui.PrivacyChk.IsChecked = [bool]$s.RemediationPrivacy; $ui.DebloatChk.IsChecked = [bool]$s.RemediationDebloat
        $ui.AdminsBox.Text = "$($s.AllowedAdmins)"; $ui.EdrBox.Text = "$($s.ExpectedEdr)"; $ui.RatBox.Text = "$($s.AllowedRemoteTools)"; $ui.ExtBox.Text = "$($s.AllowedExtensions)"
        $ui.ExceptionsBox.Text = "$($s.ExceptionsFile)"; $ui.PolicyBox.Text = "$($s.PolicyFile)"
        if ($s.Encrypt -eq 'password') { $ui.EncPass.IsChecked = $true } elseif ($s.Encrypt -eq 'certificate') { $ui.EncCert.IsChecked = $true; $ui.EncCertBox.Text = "$($s.Certificate)" }
    }
    # Fix script levels: one radio button each, with what it changes. The guided menu's "debloat and
    # telemetry only" is the level None with both boxes ticked.
    $prof = if ($s) { "$($s.RemediationProfile)" } else { '' }
    if ($prof -eq 'DebloatTelemetry') { $prof = 'None'; $ui.DebloatChk.IsChecked = $true; $ui.PrivacyChk.IsChecked = $true }
    elseif ($s -and $s.RemediationOnlyProfile) { $prof = 'None' }
    if (-not $script:Profiles.Contains($prof)) { $prof = '' }
    foreach ($k in $script:Profiles.Keys) {
        $p = $script:Profiles[$k]
        $rb = New-Object System.Windows.Controls.RadioButton
        $rb.GroupName = 'Profile'; $rb.Tag = $k; $rb.Margin = '0,3,0,3'; $rb.VerticalContentAlignment = 'Top'
        $sp = New-Object System.Windows.Controls.StackPanel
        $t1 = New-Object System.Windows.Controls.TextBlock; $t1.Text = $p.Title; $t1.FontWeight = 'SemiBold'
        $t2 = New-Object System.Windows.Controls.TextBlock; $t2.Text = $p.Text; $t2.TextWrapping = 'Wrap'; $t2.Foreground = New-Brush '#5F5A51'; $t2.FontSize = 13
        [void]$sp.Children.Add($t1); [void]$sp.Children.Add($t2)
        $rb.Content = $sp
        $rb.IsChecked = ($k -eq $prof)
        # Click, not Checked: the level already selected must tick "Write a fix script" too.
        $rb.Add_Click({ $ui.RemChk.IsChecked = $true; Update-RemPanel })
        [void]$ui.ProfilePanel.Children.Add($rb)
    }
    # One row per catalog.
    $row = 0
    foreach ($cn in $script:GuiCatalogs.Keys) {
        $c = $script:GuiCatalogs[$cn]
        $ui.CatalogGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
        $lbl = New-Object System.Windows.Controls.TextBlock
        $lbl.Text = $c.Label; $lbl.Margin = '0,4,12,4'; $lbl.VerticalAlignment = 'Center'; $lbl.FontWeight = 'SemiBold'
        [System.Windows.Controls.Grid]::SetRow($lbl, $row)
        $box = New-Object System.Windows.Controls.ComboBox
        $box.Margin = '0,4'
        [System.Windows.Controls.Grid]::SetRow($box, $row); [System.Windows.Controls.Grid]::SetColumn($box, 1)
        [void]$ui.CatalogGrid.Children.Add($lbl); [void]$ui.CatalogGrid.Children.Add($box)
        $script:CatalogBoxes[$cn] = $box
        $row++
    }
    Update-CatalogChoices -FromSettings
    Update-RemPanel
    Update-Outputs
    Update-AiInfo
    Update-AiTarget
    Update-Source
}
function Update-Source {
    # Only the part of the source that is chosen can be edited; one report per host only for a folder.
    $m = [bool]$ui.SrcMachine.IsChecked
    $ui.MachinePanel.IsEnabled = $m; $ui.MachinePanel.Opacity = if ($m) { 1 } else { 0.5 }
    $ui.SnapPanel.IsEnabled = -not $m; $ui.SnapPanel.Opacity = if ($m) { 0.5 } else { 1 }
    $t = $ui.SnapshotBox.Text.Trim()
    $ui.PerHostChk.IsEnabled = (-not $m) -and $t -and (Test-Path -LiteralPath $t -PathType Container)
    $ui.RunBtn.Content = if ($m) { 'Collect and analyze' } else { 'Analyze' }
    Update-RemPanel
}
function Get-ShippedText {
    param($C)
    if ($C.Shipped -eq 'table') { return "Table shipped with HostBadger v$($script:LocalVersion) (offline)" }
    if ($C.Shipped) { return "Copy shipped with HostBadger v$($script:LocalVersion) (offline)" }
    return ''
}
function Update-CatalogChoices {
    # Choices: the newest kept copy (if any), the shipped copy (if any), a download, or none (only for
    # catalogs with no shipped copy). Tag: kept / shipped / online / none.
    param([switch]$FromSettings)
    $s = if ($FromSettings) { Read-Settings } else { $null }
    foreach ($cn in $script:GuiCatalogs.Keys) {
        $c = $script:GuiCatalogs[$cn]; $box = $script:CatalogBoxes[$cn]
        $was = if ($box.SelectedItem) { "$($box.SelectedItem.Tag)" } else { '' }
        $kept = Find-KeptCatalog -Suffix $c.Suffix -Report $ui.ReportBox.Text
        $box.Items.Clear()
        $items = New-Object System.Collections.Generic.List[object]
        if ($kept) { $items.Add(@('kept', "Kept copy of $($kept.LastWriteTime.ToString('yyyy-MM-dd')) ($($kept.Name))")) }
        if ($c.Shipped) { $items.Add(@('shipped', (Get-ShippedText $c))) }
        $items.Add(@('online', "Download now from $($c.Site)"))
        if (-not $c.Shipped) { $items.Add(@('none', 'Not used')) }
        foreach ($i in $items) { $ci = New-Object System.Windows.Controls.ComboBoxItem; $ci.Tag = $i[0]; $ci.Content = $i[1]; [void]$box.Items.Add($ci) }
        $box.ToolTip = if ($kept) { $kept.FullName } else { $null }
        $box.Tag = $(if ($kept) { $kept.FullName } else { '' })
        # What to select: the earlier choice, else the saved mode, else the kept copy, the shipped one, none.
        $want = $was
        if (-not $want -and $s) {
            switch ("$($s.$cn)") {
                'online' { $want = 'online' }
                'off' { $want = $(if ($c.Shipped) { 'shipped' } else { 'none' }) }
                'auto' { $want = $(if ($kept -and ((Get-Date) - $kept.LastWriteTime).TotalDays -le 7) { 'kept' } else { 'online' }) }
            }
        }
        if (-not $want -or ($want -eq 'kept' -and -not $kept)) { $want = $(if ($kept) { 'kept' } elseif ($c.Shipped) { 'shipped' } else { 'none' }) }
        $box.SelectedItem = @($box.Items | Where-Object { $_.Tag -eq $want })[0]
    }
}
function Get-CatalogChoice { param([string]$Name) $b = $script:CatalogBoxes[$Name]; if ($b.SelectedItem) { return "$($b.SelectedItem.Tag)" }; return '' }
function Get-ProfileChoice { $rb = @($ui.ProfilePanel.Children | Where-Object { $_.IsChecked })[0]; if ($rb) { return "$($rb.Tag)" }; return '' }
function Update-RemPanel {
    # The choices stay editable; choosing one ticks "Write a fix script". Strict includes debloat and telemetry.
    $p = Get-ProfileChoice
    $strict = $p -eq 'Strict'
    # Leaving Strict gives back the boxes as they were before it.
    if ($strict -and -not $script:BeforeStrict) { $script:BeforeStrict = @([bool]$ui.DebloatChk.IsChecked, [bool]$ui.PrivacyChk.IsChecked) }
    if (-not $strict -and $script:BeforeStrict) { $ui.DebloatChk.IsChecked = $script:BeforeStrict[0]; $ui.PrivacyChk.IsChecked = $script:BeforeStrict[1]; $script:BeforeStrict = $null }
    foreach ($c in $ui.DebloatChk, $ui.PrivacyChk) { $c.IsEnabled = -not $strict; if ($strict) { $c.IsChecked = $true } }
    # The whole section follows the flag. On this machine the fixes are applied after the analysis (after a
    # preview and a confirmation); snapshots of other hosts only get their scripts.
    $ui.RemPanel.IsEnabled = [bool]$ui.RemChk.IsChecked
    if ($ui.SrcMachine.IsChecked -and $ui.RemChk.IsChecked) { $ui.RunBtn.Content = 'Collect, analyze and fix' }
    elseif ($ui.SrcMachine.IsChecked) { $ui.RunBtn.Content = 'Collect and analyze' }
    if ($ui.SrcMachine.IsChecked) {
        $ui.RemWarn.Text = "WARNING: this changes this machine. After the analysis the fix script is previewed; when you confirm, it is applied$(if ($script:IsAdmin) { '' } else { ' (needs administrator: Restart as administrator first)' }), with a System Restore point first (Windows PowerShell 5.1) and a rollback file of every value changed. Changes marked NOT REVERSIBLE (removed apps, LSA protection) cannot be undone by it."
        $ui.RemWarn.Foreground = New-Brush '#B3261E'; $ui.RemWarn.FontWeight = 'SemiBold'
    }
    else {
        $ui.RemWarn.Text = 'Snapshots of other hosts: one fix script per host is written next to the report, nothing is applied. Run it on that host (preview by default; -Apply as administrator changes it and writes a rollback file).'
        $ui.RemWarn.Foreground = New-Brush '#5F5A51'; $ui.RemWarn.FontWeight = 'Normal'
    }
    $rep = Get-FullPath $ui.ReportBox.Text.Trim()
    $ui.RemOutText.Text = "Written to $(($rep -replace '\.html?$', ''))_fixes: one remediate_<HOST>.ps1 per host. Preview: .\remediate_<HOST>.ps1   Apply, as administrator on that host: .\remediate_<HOST>.ps1 -Apply"
}

function Get-AnalysisParams {
    # The form as the parameters of HostBadger.ps1 (the same ones the guided menu passes).
    $ap = @{ Snapshot = $ui.SnapshotBox.Text.Trim(); OutHtml = (Get-FullPath $ui.ReportBox.Text.Trim()); NoLog = $true }
    # One report per host only for a folder (with one host it would be a copy of the report).
    if ($ui.PerHostChk.IsChecked -and $ap['Snapshot'] -and (Test-Path -LiteralPath $ap['Snapshot'] -PathType Container)) { $ap['PerHost'] = $true }
    if (-not $ui.StigChk.IsChecked) { $ap['SkipStig'] = $true } elseif (-not $ui.ShowStigChk.IsChecked) { $ap['HideStig'] = $true }
    if (-not $ui.ShowCisChk.IsChecked) { $ap['HideCis'] = $true }
    if ($ui.AcnChk.IsChecked) { $ap['Nis2Acn'] = $true }
    if ($ui.JsonlChk.IsChecked) { $ap['OutJsonl'] = $ap['OutHtml'] -replace '\.html?$', '.jsonl' }
    if ($ui.RemChk.IsChecked) {
        $ap['OutRemediation'] = ($ap['OutHtml'] -replace '\.html?$', '') + '_fixes'
        $p = Get-ProfileChoice
        if ($p -eq 'None') { $ap['RemediationOnlyProfile'] = $true } elseif ($p) { $ap['RemediationProfile'] = $p }
        if ($p -ne 'Strict') {
            if ($ui.PrivacyChk.IsChecked) { $ap['RemediationPrivacy'] = $true }
            if ($ui.DebloatChk.IsChecked) { $ap['RemediationDebloat'] = $true }
        }
    }
    foreach ($cn in $script:GuiCatalogs.Keys) {
        $c = $script:GuiCatalogs[$cn]
        switch (Get-CatalogChoice $cn) {
            'kept' { $ap[$c.File] = "$($script:CatalogBoxes[$cn].Tag)" }
            'online' { $ap[$c.Online] = $true }
        }
    }
    foreach ($pair in @(@('AllowedAdmins', $ui.AdminsBox), @('ExpectedEdr', $ui.EdrBox), @('AllowedRemoteTools', $ui.RatBox), @('AllowedExtensions', $ui.ExtBox))) {
        $l = @(Split-List $pair[1].Text); if ($l.Count) { $ap[$pair[0]] = $l }
    }
    foreach ($pair in @(@('ExceptionsFile', $ui.ExceptionsBox), @('PolicyFile', $ui.PolicyBox), @('CompareTo', $ui.CompareBox))) {
        $v = $pair[1].Text.Trim(); if ($v) { $ap[$pair[0]] = $v }
    }
    if ($ui.SnapPassBox.SecurePassword.Length -gt 0) { $ap['SnapshotPassword'] = $ui.SnapPassBox.SecurePassword.Copy() }
    # The analysis stays in the background runspace's memory for the AI buttons (never on disk).
    $ap['AiLater'] = $true
    return $ap
}

function Save-FormChoices {
    # Each run keeps the choices of the form for the next one (folders and keys are in Settings).
    # The guided menu knows the levels and DebloatTelemetry (no finding fixes, debloat and telemetry).
    $lvl = Get-ProfileChoice
    $prof = if ($lvl -ne 'None') { $lvl } elseif ($ui.DebloatChk.IsChecked -and $ui.PrivacyChk.IsChecked) { 'DebloatTelemetry' } else { '' }
    $v = @{
        SkipAcl = [bool]$ui.SkipAclChk.IsChecked; CheckUpdates = [bool]$ui.UpdatesChk.IsChecked
        PerHost = [bool]$ui.PerHostChk.IsChecked; SkipStig = -not [bool]$ui.StigChk.IsChecked; HideCis = -not [bool]$ui.ShowCisChk.IsChecked; HideStig = -not [bool]$ui.ShowStigChk.IsChecked
        Nis2Acn = [bool]$ui.AcnChk.IsChecked; Jsonl = [bool]$ui.JsonlChk.IsChecked; Remediation = [bool]$ui.RemChk.IsChecked
        RemediationProfile = $prof; RemediationOnlyProfile = ($lvl -eq 'None'); RemediationDebloat = [bool]$ui.DebloatChk.IsChecked; RemediationPrivacy = [bool]$ui.PrivacyChk.IsChecked
        GuiSource = $(if ($ui.SrcSnap.IsChecked) { 'snapshots' } else { 'machine' })
        AllowedAdmins = $ui.AdminsBox.Text.Trim(); ExpectedEdr = $ui.EdrBox.Text.Trim(); AllowedRemoteTools = $ui.RatBox.Text.Trim(); AllowedExtensions = $ui.ExtBox.Text.Trim()
        ExceptionsFile = $ui.ExceptionsBox.Text.Trim(); PolicyFile = $ui.PolicyBox.Text.Trim()
    }
    # A catalog keeps its saved mode unless the form now asks for something else (a download, or none).
    $old = Read-Settings
    foreach ($cn in $script:GuiCatalogs.Keys) {
        $m = switch (Get-CatalogChoice $cn) { 'online' { 'online' } 'none' { 'off' } 'shipped' { 'off' } default { 'kept' } }
        if ($old -and "$($old.$cn)" -eq 'auto' -and $m -ne 'off') { $m = 'auto' }
        $v[$cn] = $m
    }
    try { Write-Settings $v } catch { Add-Log "The choices of the form were not saved: $($_.Exception.Message)" }
}

# ---------------- The Settings window.
function Set-KeyState {
    param($Text, [string]$Name)
    $user = [Environment]::GetEnvironmentVariable($Name, 'User')
    $now = [Environment]::GetEnvironmentVariable($Name, 'Process')
    $Text.Text = if ($user) { "$Name is remembered for your Windows account. Type a new key to replace it; untick Remember to forget it." } elseif ($now) { "$Name is set for this window only." } else { "$Name is not set." }
}
function Save-Key {
    # The key for this window, and for the Windows account when asked (never in the settings file).
    param($Box, $Remember, [string]$Name)
    $k = (Get-PlainSecret $Box).Trim()
    $user = [Environment]::GetEnvironmentVariable($Name, 'User')
    if ($k) { [Environment]::SetEnvironmentVariable($Name, $k, 'Process') }
    if ($Remember.IsChecked) {
        $v = if ($k) { $k } else { [Environment]::GetEnvironmentVariable($Name, 'Process') }
        if ($v -and $v -ne $user) { [Environment]::SetEnvironmentVariable($Name, $v, 'User'); Add-Log "$Name remembered for your Windows account." }
    }
    elseif ($user) { [Environment]::SetEnvironmentVariable($Name, $null, 'User'); Add-Log "$Name forgotten for your Windows account (still set for this window)." }
}
function New-SettingsWindow {
    $sw = New-XamlWindow $settingsXaml
    $su = $sw.Ui
    $s = Read-Settings
    $su.SetSnapDir.Text = Get-SnapshotDir
    $su.SetRepDir.Text = Get-ReportDir
    $su.SetPathText.Inlines.Add((New-Object System.Windows.Documents.Run 'Saved in '))
    $link = New-Object System.Windows.Documents.Hyperlink (New-Object System.Windows.Documents.Run $script:SettingsPath)
    $link.Foreground = New-Brush '#8A5A00'
    $link.Add_Click({ if (Test-Path -LiteralPath $script:SettingsPath) { try { Invoke-Item -LiteralPath $script:SettingsPath } catch { Add-Log "Not opened: $($_.Exception.Message)" } } })
    $su.SetPathText.Inlines.Add($link)
    $su.SetPathText.Inlines.Add((New-Object System.Windows.Documents.Run ', shared with the guided menu (menu 8).'))
    # Editable: any Gemini model name; the list offers HostBadger's default and the saved one.
    foreach ($m in @($script:DefaultModel, "$(if ($s) { $s.Model })") | Select-Object -Unique) { if ($m) { [void]$su.SetModel.Items.Add($m) } }
    $su.SetModel.Text = if ($s -and $s.Model) { "$($s.Model)" } else { $script:DefaultModel }
    foreach ($n in @(1..6) + 0) { [void]$su.SetAttempts.Items.Add("$n") }
    $su.SetAttempts.SelectedItem = if ($s -and "$($s.AiMaxAttempts)" -match '^[0-6]$') { "$($s.AiMaxAttempts)" } else { '3' }
    $su.SetAiStig.IsChecked = [bool]($s -and $s.AiIncludeStig)
    $su.SetGeminiRemember.IsChecked = [bool][Environment]::GetEnvironmentVariable('GEMINI_API_KEY', 'User')
    $su.SetNvdRemember.IsChecked = [bool][Environment]::GetEnvironmentVariable('NVD_API_KEY', 'User')
    Set-KeyState $su.SetGeminiState 'GEMINI_API_KEY'
    Set-KeyState $su.SetNvdState 'NVD_API_KEY'
    $row = 0
    $sw.Boxes = @{}
    foreach ($cn in $script:GuiCatalogs.Keys) {
        $c = $script:GuiCatalogs[$cn]
        $su.SetCatalogGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
        $lbl = New-Object System.Windows.Controls.TextBlock
        $lbl.Text = $c.Label; $lbl.Margin = '0,4,12,4'; $lbl.VerticalAlignment = 'Center'; $lbl.FontWeight = 'SemiBold'
        [System.Windows.Controls.Grid]::SetRow($lbl, $row)
        $box = New-Object System.Windows.Controls.ComboBox
        $box.Margin = '0,4'
        foreach ($m in $script:CatalogModes.Keys) {
            $ci = New-Object System.Windows.Controls.ComboBoxItem; $ci.Tag = $m
            $ci.Content = if ($m -eq 'off') { "Never download: $(if ($c.Shipped) { 'the shipped copy' } else { 'not used' })" } elseif ($m -eq 'kept') { "Newest kept copy, else $(if ($c.Shipped) { 'the shipped copy' } else { 'not used' })" } else { $script:CatalogModes[$m] }
            [void]$box.Items.Add($ci)
        }
        $cur = if ($s -and "$($s.$cn)" -in $script:CatalogModes.Keys) { "$($s.$cn)" } else { 'kept' }
        $box.SelectedItem = @($box.Items | Where-Object { $_.Tag -eq $cur })[0]
        [System.Windows.Controls.Grid]::SetRow($box, $row); [System.Windows.Controls.Grid]::SetColumn($box, 1)
        [void]$su.SetCatalogGrid.Children.Add($lbl); [void]$su.SetCatalogGrid.Children.Add($box)
        $sw.Boxes[$cn] = $box
        $row++
    }
    if ($s -and $s.Encrypt -eq 'password') { $su.SetEncPass.IsChecked = $true } elseif ($s -and $s.Encrypt -eq 'certificate') { $su.SetEncCert.IsChecked = $true } elseif ($s -and $s.Encrypt -eq 'none') { $su.SetEncNone.IsChecked = $true }
    $su.SetCert.Text = if ($s) { "$($s.Certificate)" } else { '' }
    return $sw
}
function Save-SettingsWindow {
    $sw = $script:SetWin; $su = $sw.Ui
    $att = "$($su.SetAttempts.SelectedItem)"
    $enc = if ($su.SetEncPass.IsChecked) { 'password' } elseif ($su.SetEncCert.IsChecked) { 'certificate' } elseif ($su.SetEncNone.IsChecked) { 'none' } else { 'ask' }
    $model = $su.SetModel.Text.Trim()
    $v = @{
        SnapshotDir = $su.SetSnapDir.Text.Trim(); ReportDir = $su.SetRepDir.Text.Trim()
        Model = $(if ($model -eq $script:DefaultModel) { '' } else { $model }); AiMaxAttempts = $(if ($att -eq '3') { '' } else { $att }); AiIncludeStig = [bool]$su.SetAiStig.IsChecked
        Encrypt = $enc; Certificate = $su.SetCert.Text.Trim()
    }
    foreach ($cn in $sw.Boxes.Keys) { $v[$cn] = "$($sw.Boxes[$cn].SelectedItem.Tag)" }
    Write-Settings $v
    Save-Key $su.SetGeminiKey $su.SetGeminiRemember 'GEMINI_API_KEY'
    Save-Key $su.SetNvdKey $su.SetNvdRemember 'NVD_API_KEY'
    Add-Log "Settings saved: $($script:SettingsPath)."
    $sw.Window.Close()
}
function Show-Settings {
    # Modal; its buttons reach it through $script:SetWin (a closure would not see this script's functions).
    $script:SetWin = New-SettingsWindow
    $su = $script:SetWin.Ui
    $script:SetWin.Window.Owner = $window
    $su.SetSnapDirBtn.Add_Click({ $d = New-Object System.Windows.Forms.FolderBrowserDialog; if ($d.ShowDialog() -eq 'OK') { $script:SetWin.Ui.SetSnapDir.Text = $d.SelectedPath } })
    $su.SetRepDirBtn.Add_Click({ $d = New-Object System.Windows.Forms.FolderBrowserDialog; if ($d.ShowDialog() -eq 'OK') { $script:SetWin.Ui.SetRepDir.Text = $d.SelectedPath } })
    $su.SetCancelBtn.Add_Click({ $script:SetWin.Window.Close() })
    $su.SetSaveBtn.Add_Click({ Save-SettingsWindow })
    [void]$script:SetWin.Window.ShowDialog()
    $script:SetWin = $null
    # The form follows the new folders and catalog modes.
    $ui.CollectDirBox.Text = Get-SnapshotDir
    Select-LatestSnapshot (Get-SnapshotDir)
    $ui.ReportBox.Text = Join-Path (Get-ReportDir) "hostbadger_$(Get-Stamp).html"
    foreach ($b in $script:CatalogBoxes.Values) { $b.SelectedItem = $null }
    Update-CatalogChoices -FromSettings
    if ($ui.EncNone.IsChecked) { $s = Read-Settings; if ($s.Encrypt -eq 'password') { $ui.EncPass.IsChecked = $true } elseif ($s.Encrypt -eq 'certificate') { $ui.EncCert.IsChecked = $true; $ui.EncCertBox.Text = "$($s.Certificate)" } }
    Update-RemPanel
    Update-AiInfo
    Update-Source
}

# ---------------- Actions.
function Invoke-Analyze {
    $ap = Get-AnalysisParams
    if (-not $ap['Snapshot'] -or -not (Test-Path -LiteralPath $ap['Snapshot'])) { [void][System.Windows.MessageBox]::Show('Choose a snapshot file, zip or folder first.', 'HostBadger'); return }
    $isDir = (Get-Item -LiteralPath $ap['Snapshot']).PSIsContainer
    $hbx = if ($isDir) { @(Get-ChildItem -LiteralPath $ap['Snapshot'] -Recurse -File -Filter 'hostsnapshot_*.hbx' -ErrorAction SilentlyContinue) } else { @(Get-Item -LiteralPath $ap['Snapshot'] | Where-Object { $_.Extension -eq '.hbx' }) }
    if ($hbx.Count -gt 0 -and -not $ap['SnapshotPassword']) { [void][System.Windows.MessageBox]::Show("$($hbx.Count) encrypted snapshot(s): type their password first.", 'HostBadger'); return }
    $dir = Split-Path -Parent $ap['OutHtml']
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $script:Kept = $false
    $script:Pending = $ap['OutHtml']
    Start-GuiTask -Label 'Analyzing' -Work $script:RunScript -Arguments @((Join-Path $root 'HostBadger.ps1'), $ap) -Done {
        param($t)
        $ok = Test-Path -LiteralPath $script:Pending
        $script:Kept = $ok
        Set-Busy $false $(if ($ok) { 'Report ready' } else { 'The analysis did not finish' })
        if ($ok) {
            $script:LastReport = $script:Pending
            Write-GuiLog -Path ($script:LastReport -replace '\.html?$', '.log') -Lines $t.Lines
            $ui.ReportBox.Text = Join-Path (Split-Path -Parent $script:LastReport) "hostbadger_$(Get-Stamp).html"
            Update-CatalogChoices
            Update-RemPanel
        }
        Update-Outputs
        if ($ok -and $script:ApplyAfter) { $script:ApplyAfter = $false; Invoke-FixPreview }
    }
}
function Write-GuiLog {
    # The run log next to the report (the window shows the same lines).
    param([string]$Path, $Lines)
    try { [System.IO.File]::WriteAllText($Path, (($Lines -join [Environment]::NewLine) + [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false))); Add-Log "Run log: $Path" } catch { }
}

function Invoke-Ai {
    param([bool]$Send)
    # With no analysis in memory (a report from an earlier session), the snapshot is analyzed again in
    # the same run and the report rewritten with the AI section: the HTML holds the summary, and the
    # analysis is deterministic, so the findings are the same.
    if ($script:Kept) { $ai = @{ AiContinue = $true }; $target = $script:LastReport }
    else {
        $ai = Get-AnalysisParams
        $ai.Remove('AiLater')
        if (-not $ai['Snapshot'] -or -not (Test-Path -LiteralPath $ai['Snapshot'])) { $latest = Find-LatestSnapshot (Get-SnapshotDir); if ($latest) { $ai['Snapshot'] = $latest.FullName } }
        if (-not $ai['Snapshot'] -or -not (Test-Path -LiteralPath $ai['Snapshot'])) { [void][System.Windows.MessageBox]::Show('No snapshot to analyze: choose one, or collect this machine first.', 'HostBadger'); return }
        if ($script:LastReport -and (Test-Path -LiteralPath $script:LastReport)) {
            $ai['OutHtml'] = $script:LastReport
            if ($ai['OutJsonl']) { $ai['OutJsonl'] = $script:LastReport -replace '\.html?$', '.jsonl' }
            if ($ai['OutRemediation']) { $ai['OutRemediation'] = ($script:LastReport -replace '\.html?$', '') + '_fixes' }
        }
        $target = $ai['OutHtml']
        Add-Log "No analysis in memory: $($ai['Snapshot']) is analyzed again into $target, then the AI step."
    }
    $s = Read-Settings
    if ($s -and $s.Model) { $ai['Model'] = "$($s.Model)" }
    if ($s -and "$($s.AiMaxAttempts)" -match '^\d+$') { $ai['AiMaxAttempts'] = [int]"$($s.AiMaxAttempts)" }
    if ($ui.StigChk.IsChecked -and $s -and $s.AiIncludeStig) { $ai['AiIncludeStig'] = $true }
    if ($Send) {
        if (-not $env:GEMINI_API_KEY) { [void][System.Windows.MessageBox]::Show('Set the Gemini API key in Settings first (for this window, or remembered for your Windows account).', 'HostBadger'); return }
        $answer = [System.Windows.MessageBox]::Show("The findings go to Gemini ($(if ($ai['Model']) { $ai['Model'] } else { $script:DefaultModel })) with host names, domains, accounts, groups, SIDs, paths, service and task names and addresses replaced by tokens; a leak check refuses to send if one survives. The exact text is saved next to the report first.`n`nTip: AI: dry run writes that text without sending it.`n`nSend now?", 'HostBadger', 'YesNo', 'Question')
        if ("$answer" -ne 'Yes') { return }
        $ai['SendToAI'] = $true
    }
    else { $ai['AiDryRun'] = $target -replace '\.html?$', '_ai_prompt.txt' }
    if (-not $ui.StigChk.IsChecked) { $ai['SkipStig'] = $true }
    $script:LastReport = $target
    Start-GuiTask -Label $(if ($Send) { 'Sending to Gemini' } else { 'Writing the AI prompt (dry run)' }) -Work $script:RunScript -Arguments @((Join-Path $root 'HostBadger.ps1'), $ai) -Done {
        param($t)
        # A send uses the kept analysis up; a dry run leaves it for a send.
        if (@($t.Lines | Where-Object { $_ -like 'No analysis kept*' -or $_ -like 'AI section added*' }).Count) { $script:Kept = $false }
        Set-Busy $false 'Ready'
        Update-Outputs
    }
}

function Invoke-Run {
    # This machine: collect, then analyze the new snapshot. Snapshots already collected: analyze them.
    Save-FormChoices
    if ($ui.RemChk.IsChecked -and (Get-ProfileChoice) -eq 'None' -and -not $ui.DebloatChk.IsChecked -and -not $ui.PrivacyChk.IsChecked) {
        [void][System.Windows.MessageBox]::Show('Fix scripts: with "No fix of the findings", tick Debloat, Disable telemetry or both.', 'HostBadger'); return
    }
    $script:ApplyAfter = $ui.RemChk.IsChecked -and $ui.SrcMachine.IsChecked
    if ($script:ApplyAfter -and -not $script:IsAdmin) {
        $answer = [System.Windows.MessageBox]::Show("Applying the fixes needs administrator rights (Restart as administrator, at the top).`n`nGo on and only write the fix script, without applying it?", 'HostBadger', 'YesNo', 'Warning')
        if ("$answer" -ne 'Yes') { return }
        $script:ApplyAfter = $false
    }
    if ($ui.SrcMachine.IsChecked) { Invoke-Collect -ThenAnalyze } else { Invoke-Analyze }
}

function Invoke-FixPreview {
    # This machine, after its analysis: preview the fix script, then ask before applying it.
    $dir = ($script:LastReport -replace '\.html?$', '') + '_fixes'
    $fix = @(Get-ChildItem -LiteralPath $dir -Filter 'remediate_*.ps1' -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($fix.Count -eq 0) { Add-Log 'Fix: nothing on this machine has a fix to apply.'; return }
    $script:FixScript = $fix[0].FullName
    Add-Log "Fix: preview of $($script:FixScript) (nothing changes yet)."
    Start-GuiTask -Label 'Fix preview' -Work $script:RunScript -Arguments @($script:FixScript, @{}) -Done {
        param($t)
        Set-Busy $false 'Ready'
        $would = @($t.Lines | Where-Object { $_ -match '^WOULD ' })
        $noUndo = @($would | Where-Object { $_ -match 'NOT REVERSIBLE' })
        if ($would.Count -eq 0) { Add-Log 'Fix: this machine already has every setting of the script.'; return }
        $msg = "WARNING: $($would.Count) change(s) to THIS machine, listed in the log$(if ($noUndo.Count) { ", $($noUndo.Count) of them NOT REVERSIBLE (removed apps come back only from the Microsoft Store)" }).`n`nA System Restore point is made first (Windows PowerShell 5.1 on a Windows client) and every previous value is saved in a rollback file. Some changes take effect after a restart.`n`nApply them now?"
        if ("$([System.Windows.MessageBox]::Show($msg, 'HostBadger: apply the fixes', 'YesNo', 'Warning', 'No'))" -ne 'Yes') { Add-Log 'Fix: not applied, nothing changed.'; return }
        Invoke-FixApply
    }
}
function Invoke-FixApply {
    $script:Rollback = Join-Path (Split-Path -Parent $script:FixScript) 'rollback.json'
    Start-GuiTask -Label 'Applying the fixes' -Work $script:RunScript -Arguments @($script:FixScript, @{ Apply = $true; RestorePoint = $true; RollbackFile = $script:Rollback }) -Done {
        param($t)
        Set-Busy $false 'Fixes applied'
        Update-Outputs
        $failed = @($t.Lines | Where-Object { $_ -match '^FAILED ' }).Count
        $undo = "To undo, as administrator: & '$($script:FixScript)' -Restore '$($script:Rollback)' -Apply"
        Add-Log $undo
        [void][System.Windows.MessageBox]::Show("Fixes applied$(if ($failed) { ", $failed failed (see the log)" }). Restart the machine for the settings Windows reads at startup.`n`nPrevious values: $($script:Rollback)`n$undo", 'HostBadger', 'OK', $(if ($failed) { 'Warning' } else { 'Information' }))
    }
}
function Invoke-Collect {
    param([switch]$ThenAnalyze)
    $script:ThenAnalyze = [bool]$ThenAnalyze
    $p = @{ OutDir = (Get-FullPath $ui.CollectDirBox.Text.Trim()) }
    if (-not $p.OutDir) { $p.OutDir = Get-SnapshotDir }
    if ($ui.SkipAclChk.IsChecked) { $p['SkipAcl'] = $true }
    if ($ui.UpdatesChk.IsChecked) { $p['CheckUpdates'] = $true }
    if ($ui.EncPass.IsChecked) {
        $pw = Get-PlainSecret $ui.EncPassBox
        if (-not $pw) { [void][System.Windows.MessageBox]::Show('Type the password for the snapshot.', 'HostBadger'); return }
        $p['EncryptPassword'] = $pw
    }
    elseif ($ui.EncCert.IsChecked) {
        if (-not $ui.EncCertBox.Text.Trim()) { [void][System.Windows.MessageBox]::Show('Give the .cer path or the thumbprint of the certificate.', 'HostBadger'); return }
        $p['EncryptCertificate'] = $ui.EncCertBox.Text.Trim()
    }
    Start-GuiTask -Label 'Collecting this machine (read only)' -Work $script:RunScript -Arguments @((Join-Path $root 'Collect-HostSnapshot.ps1'), $p) -Done {
        param($t)
        $snap = @($t.Lines | Where-Object { $_ -like 'Snapshot: *' } | ForEach-Object { $_.Substring(10).Trim() }) | Select-Object -Last 1
        if ($snap) {
            $script:LastSnapshot = $snap
            $ui.SnapshotBox.Text = $snap
            $ui.SnapshotNote.Text = "The snapshot just collected ($((Get-Item -LiteralPath $snap).LastWriteTime.ToString('yyyy-MM-dd HH:mm')))."
            if ($ui.EncPass.IsChecked) { $ui.SnapPassBox.Password = $ui.EncPassBox.Password }
            Update-Outputs
            if ($script:ThenAnalyze) { Invoke-Analyze; return }
            Set-Busy $false 'Snapshot ready'
        }
        else { Set-Busy $false 'The collection did not finish'; Update-Outputs }
    }
}

# ---------------- Updates: git clone (fetch, compare, pull --ff-only) or the version on the main branch.
$script:UpdateCheck = {
    param([string]$Root, [string]$Local)
    $r = [pscustomobject]@{ Kind = 'update'; Local = $Local; Latest = ''; Behind = -1; Git = $false; Dirty = $false; Branch = ''; Error = '' }
    $gitOk = $false
    if (Test-Path -LiteralPath (Join-Path $Root '.git')) { try { $null = git --version 2>&1; $gitOk = ($LASTEXITCODE -eq 0) } catch { $gitOk = $false } }
    if ($gitOk) {
        $r.Git = $true
        "git fetch from the HostBadger repository (origin)..."
        $f = @(git -C $Root fetch --quiet origin 2>&1)
        if ($LASTEXITCODE -ne 0) { $r.Error = "git fetch failed: $($f -join ' ')"; return $r }
        # Releases are on main: compare with origin/main whatever the clone tracks.
        $r.Branch = "$(@(git -C $Root rev-parse --abbrev-ref HEAD 2>&1)[0])".Trim()
        $b = @(git -C $Root rev-list --count 'HEAD..origin/main' 2>&1)
        if ($LASTEXITCODE -eq 0) { $r.Behind = [int]"$($b[0])" }
        $r.Dirty = @(git -C $Root status --porcelain --untracked-files=no 2>&1 | Where-Object { "$_".Trim() }).Count -gt 0
        $up = (@(git -C $Root show 'origin/main:HostBadger.ps1' 2>&1) -join "`n")
        if ($up -match "\`$script:HostBadgerVersion = '([\d.]+)'") { $r.Latest = $Matches[1] }
        return $r
    }
    "Reading the version on the main branch from raw.githubusercontent.com..."
    . (Join-Path $Root 'lib\Common.ps1')
    . (Join-Path $Root 'lib\AI.ps1')
    $r.Latest = Get-HostBadgerLatestVersion
    if (-not $r.Latest) { $r.Error = 'the version on GitHub could not be read' }
    return $r
}
$script:UpdatePull = {
    param([string]$Root)
    git -C $Root pull --ff-only origin main 2>&1 | ForEach-Object { "$_" }
    [pscustomobject]@{ Kind = 'pulled'; Ok = ($LASTEXITCODE -eq 0) }
}
function Invoke-UpdateCheck {
    Start-GuiTask -Label 'Checking for updates' -Work $script:UpdateCheck -Arguments @($root, $script:LocalVersion) -Done {
        param($t)
        $r = @($t.Results | Where-Object { $_.Kind -eq 'update' })[0]
        $ui.UpdateBtn.Visibility = 'Collapsed'
        if (-not $r -or $r.Error) { $ui.UpdateText.Text = "Could not check: $(if ($r) { $r.Error } else { 'no answer' })"; return }
        if ($r.Git) {
            if ($r.Behind -gt 0) {
                $ui.UpdateText.Text = "$($r.Behind) new commit(s) on GitHub$(if ($r.Latest) { " (version $($r.Latest))" })."
                if ($r.Branch -ne 'main') { $ui.UpdateText.Text += " This copy is on the branch $($r.Branch): update it with git yourself." }
                elseif ($r.Dirty) { $ui.UpdateText.Text += ' This folder has local changes: update it with git yourself.' }
                else { $ui.UpdateBtn.Visibility = 'Visible' }
            }
            elseif ($r.Behind -eq 0) { $ui.UpdateText.Text = "Up to date: nothing new on GitHub (v$($r.Local))." }
            else { $ui.UpdateText.Text = 'The main branch of GitHub could not be compared with this copy.' }
            return
        }
        $newer = $false
        try { $newer = [version]$r.Latest -gt [version]$r.Local } catch { }
        $ui.UpdateText.Text = if ($newer) { "Version $($r.Latest) is on GitHub (this is v$($r.Local)): download it from github.com/g4bri-3l3/HostBadger, or clone it with git to update from here." } else { "Up to date (v$($r.Local))." }
    }
}
function Invoke-Update {
    $answer = [System.Windows.MessageBox]::Show("git pull --ff-only origin main in $root`n`nIt takes the new commits of the main branch from GitHub (origin), only if this copy can move forward without a merge. This folder has no local changes, so nothing of yours is overwritten. Then close and start HostBadger again.`n`nUpdate now?", 'HostBadger', 'YesNo', 'Question')
    if ("$answer" -ne 'Yes') { return }
    Start-GuiTask -Label 'Updating (git pull --ff-only)' -Work $script:UpdatePull -Arguments @($root) -Done {
        param($t)
        $r = @($t.Results | Where-Object { $_.Kind -eq 'pulled' })[0]
        $ui.UpdateBtn.Visibility = 'Collapsed'
        $ui.UpdateText.Text = if ($r -and $r.Ok) { 'Updated: close this window and start HostBadger again.' } else { 'The update did not apply: see the log.' }
    }
}

# ---------------- Wiring.
$ui.SnapFolderBtn.Add_Click({ $d = New-Object System.Windows.Forms.FolderBrowserDialog; if ($d.ShowDialog() -eq 'OK') { $ui.SnapshotBox.Text = $d.SelectedPath; $ui.SnapshotNote.Text = 'A folder: the newest snapshot of each host in it is analyzed.' } })
$ui.SnapFileBtn.Add_Click({ $d = New-Object Microsoft.Win32.OpenFileDialog; $d.Filter = 'HostBadger snapshots|hostsnapshot_*.zip;hostsnapshot_*.json;hostsnapshot_*.hbx|All files|*.*'; $d.InitialDirectory = Get-SnapshotDir; if ($d.ShowDialog()) { $ui.SnapshotBox.Text = $d.FileName; $ui.SnapshotNote.Text = '' } })
$ui.CollectDirBtn.Add_Click({ $d = New-Object System.Windows.Forms.FolderBrowserDialog; if ($d.ShowDialog() -eq 'OK') { $ui.CollectDirBox.Text = $d.SelectedPath } })
$ui.StigChk.Add_Click({ $ui.ShowStigChk.IsEnabled = [bool]$ui.StigChk.IsChecked })
$ui.RemChk.Add_Click({ Update-RemPanel })
$ui.DebloatChk.Add_Click({ if ($ui.DebloatChk.IsChecked) { $ui.RemChk.IsChecked = $true }; Update-RemPanel })
$ui.PrivacyChk.Add_Click({ if ($ui.PrivacyChk.IsChecked) { $ui.RemChk.IsChecked = $true }; Update-RemPanel })
$ui.ReportBox.Add_LostFocus({ Update-CatalogChoices; Update-RemPanel })
$ui.SrcMachine.Add_Checked({ Update-Source })
$ui.SrcSnap.Add_Checked({ Update-Source })
$ui.SnapshotBox.Add_TextChanged({ Update-Source })
$ui.RunBtn.Add_Click({ Invoke-Run })
$ui.SafetyBtn.Add_Click({ Start-GuiTask -Label 'Safety review' -Work $script:RunScript -Arguments @((Join-Path $root 'Test-HostBadgerSafety.ps1'), @{}) -Done { } })
$ui.OpenBtn.Add_Click({ if ($script:LastReport -and (Test-Path -LiteralPath $script:LastReport)) { Invoke-Item -LiteralPath $script:LastReport } })

$ui.SettingsBtn.Add_Click({ Show-Settings })
$ui.AiPickBtn.Add_Click({
        $d = New-Object Microsoft.Win32.OpenFileDialog; $d.Filter = 'HostBadger reports|*.html'
        $d.InitialDirectory = if ($script:LastReport) { Split-Path -Parent $script:LastReport } else { Get-ReportDir }
        if ($d.ShowDialog()) {
            # The analysis in memory belongs to the last run's report only.
            if ($d.FileName -ne $script:LastReport) { $script:Kept = $false }
            $script:LastReport = $d.FileName
            Update-AiTarget; Update-Outputs
        }
    })
$ui.SnapshotBox.Add_TextChanged({ Update-AiTarget })
$ui.AiDryBtn.Add_Click({ Invoke-Ai $false })
$ui.AiSendBtn.Add_Click({ Invoke-Ai $true })
$ui.UpdateCheckBtn.Add_Click({ Invoke-UpdateCheck })
$ui.UpdateBtn.Add_Click({ Invoke-Update })
$ui.ElevateBtn.Add_Click({
        # The same window, as administrator (Windows asks to confirm), in the same folder.
        $exe = (Get-Process -Id $PID).Path
        try {
            Start-Process -FilePath $exe -Verb RunAs -WorkingDirectory $PWD.ProviderPath -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
            $window.Close()
        }
        catch { Add-Log "Not restarted: $($_.Exception.Message)" }
    })
$window.Add_Activated({ if (-not $script:Task -and $ui.SnapshotNote.Text -like 'The newest snapshot*') { Select-LatestSnapshot (Get-SnapshotDir) } })
$window.Add_Closing({ $script:Timer.Stop(); if ($script:Task) { try { $script:Task.Ps.Stop() } catch { } } })

Initialize-Form
Add-Log "HostBadger v$($script:LocalVersion). Choose what to analyze (this machine, or snapshots already collected) and press the yellow button."
if ($NoShow) {
    $sw = New-SettingsWindow
    "GUI ready: $($ui.Count) controls, $($script:CatalogBoxes.Count) catalogs, version $($script:LocalVersion); settings: $($sw.Ui.Count) controls, $($sw.Boxes.Count) catalogs, $($ui.ProfilePanel.Children.Count) fix levels"
    $sw.Window.Close()
    $script:Rs.Dispose()
    return
}
[void]$window.ShowDialog()
$script:Rs.Dispose()
