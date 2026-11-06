<#
.SYNOPSIS
    HostBadger in a window: collect and analyze this machine, or analyze
    snapshots already collected; add the AI summary, run the safety review,
    check for a newer HostBadger.

.DESCRIPTION
    The same steps as the guided menu (Start-HostBadger.ps1), with the answers
    as a form. It runs Collect-HostSnapshot.ps1 and HostBadger.ps1 with the
    parameters chosen here, in the background of this window, and shows what
    they print. The report is the usual HTML file, opened in the browser; the
    Results tab shows its findings (from the CSV next to it) by category, with
    filters and the details of each one.

    The one step that changes the machine is "Fix what the analysis finds" on
    this machine: the fix script is previewed, then applied only after a
    warning and Yes (as administrator, with a restore point and a rollback
    file). The one thing Settings can write outside HostBadger's folder is what you ask it
    to remember: GEMINI_API_KEY / NVD_API_KEY as environment variables of your
    Windows account (never in the settings file).

    Network: only what you ask for. "Download" on a catalog makes the analysis
    fetch it (the address is named next to it); "Send to Gemini" sends the
    pseudonymized findings; "Check for updates" asks the HostBadger repository
    on GitHub (git fetch of a git clone, otherwise one GET of HostBadger.ps1
    from raw.githubusercontent.com); "Update" runs git pull --ff-only origin
    main in a git clone on main with no local changes. The same check runs at
    every start only if it is ticked in Settings (off by default).

    The saved settings of the guided menu (output\hostbadger-settings.json,
    menu 8) fill the form. Settings writes them back, and each run saves the
    choices of the form, so the window opens as it was left.
.PARAMETER NoShow
    Build the windows without showing them, then close (used by the tests).
.PARAMETER StartIn
    The folder to work in. Restart as administrator passes the folder the window
    was started from: an elevated process starts in System32, where it would
    find neither the settings nor the kept catalogs.
#>
[CmdletBinding()]
param([switch]$NoShow, [string]$StartIn = '')

$ErrorActionPreference = 'Stop'
if ($StartIn -and (Test-Path -LiteralPath $StartIn -PathType Container)) { Set-Location -LiteralPath $StartIn }
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
$script:CatalogModes = [ordered]@{ auto = 'Kept copy under a week old, else download'; kept = 'Newest kept copy whatever its age, else the shipped one or none'; online = 'Download at every analysis'; off = 'Never download: shipped copy or none' }

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
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="RenderTransform"><Setter.Value><TranslateTransform X="2" Y="2"/></Setter.Value></Setter></Trigger>
              <!-- Disabled: dashed-looking grey ink, no shadow, so it does not read as pressable. -->
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="b" Property="Background" Value="#EFEBE2"/>
                <Setter TargetName="b" Property="BorderBrush" Value="#B9B2A5"/>
                <Setter Property="Foreground" Value="#8C857A"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Effect" Value="{x:Null}"/></Trigger>
        <Trigger Property="IsPressed" Value="True"><Setter Property="Effect" Value="{x:Null}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#F2B632"/>
    </Style>
    <!-- Something that changes or stops: a red tint while it can be pressed. -->
    <Style x:Key="Danger" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#FBD9D2"/>
    </Style>
    <!-- Secondary actions (file pickers, settings): lighter, so the main action stands out. -->
    <Style x:Key="Ghost" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="BorderThickness" Value="2"/>
      <Setter Property="Padding" Value="10,4"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Effect" Value="{x:Null}"/>
    </Style>
    <!-- The header actions: one row of buttons of the same size (their UniformGrid sets the width). -->
    <Style x:Key="Header" TargetType="Button" BasedOn="{StaticResource Ghost}">
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Height" Value="28"/>
      <Setter Property="Padding" Value="6,0"/>
      <Setter Property="Margin" Value="6,0,0,0"/>
    </Style>
    <!-- Slim scroll bars in the colors of the page, instead of the grey Windows ones. -->
    <Style x:Key="ThumbInk" TargetType="Thumb">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Thumb"><Border x:Name="t" Background="#8C857A" CornerRadius="0"/>
            <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="t" Property="Background" Value="#161513"/></Trigger></ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ScrollBar">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollBar">
            <Border Background="#E8E2D4" Width="8">
              <Track x:Name="PART_Track" IsDirectionReversed="True">
                <Track.Thumb><Thumb Style="{StaticResource ThumbInk}"/></Track.Thumb>
              </Track>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="Orientation" Value="Horizontal">
          <Setter Property="Template">
            <Setter.Value>
              <ControlTemplate TargetType="ScrollBar">
                <Border Background="#E8E2D4" Height="8">
                  <Track x:Name="PART_Track" IsDirectionReversed="False">
                    <Track.Thumb><Thumb Style="{StaticResource ThumbInk}"/></Track.Thumb>
                  </Track>
                </Border>
              </ControlTemplate>
            </Setter.Value>
          </Setter>
        </Trigger>
      </Style.Triggers>
    </Style>
    <!-- A choice drawn as a card (the fix levels): the whole card is the click target, the chosen one is inked. -->
    <Style x:Key="OptionCard" TargetType="RadioButton">
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Margin" Value="0,0,0,8"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="b" Background="#FFFDF8" BorderBrush="#CFC8BA" BorderThickness="2" Padding="12,8">
              <DockPanel>
                <Border x:Name="dot" DockPanel.Dock="Left" Width="16" Height="16" Margin="0,2,12,0" VerticalAlignment="Top" BorderBrush="#161513" BorderThickness="2" CornerRadius="8" Background="#FFFDF8">
                  <Ellipse x:Name="fill" Width="6" Height="6" Fill="#161513" Visibility="Collapsed"/>
                </Border>
                <ContentPresenter/>
              </DockPanel>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#FFF6DE"/></Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="b" Property="Background" Value="#FBE7B5"/>
                <Setter TargetName="b" Property="BorderBrush" Value="#161513"/>
                <Setter TargetName="fill" Property="Visibility" Value="Visible"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <!-- A warning box: red bar on the left, light red paper. -->
    <Style x:Key="Callout" TargetType="Border">
      <Setter Property="Background" Value="#FBEAE7"/>
      <Setter Property="BorderBrush" Value="#B3261E"/>
      <Setter Property="BorderThickness" Value="6,0,0,0"/>
      <Setter Property="Padding" Value="14,10"/>
      <Setter Property="Margin" Value="0,0,0,8"/>
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
    <!-- A card without the shadow, for what scrolls (an effect would be redrawn at every scroll). -->
    <Style x:Key="Flat" TargetType="Border">
      <Setter Property="Background" Value="#FFFDF8"/>
      <Setter Property="BorderBrush" Value="#161513"/>
      <Setter Property="BorderThickness" Value="3"/>
    </Style>
    <Style x:Key="ReadOnlyText" TargetType="TextBox">
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Padding" Value="0"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="Margin" Value="0,0,0,8"/>
    </Style>
    <!-- The font of the tab goes on its header only: set on the TabItem it would reach the whole page. -->
    <Style TargetType="TabItem">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="b" Background="#FFFDF8" BorderBrush="#161513" BorderThickness="3" Padding="20,6" Margin="0,0,10,0" Cursor="Hand">
              <ContentPresenter ContentSource="Header" HorizontalAlignment="Center" TextElement.FontFamily="Bahnschrift, Segoe UI" TextElement.FontSize="16" TextElement.FontWeight="Bold"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#FBE7B5"/></Trigger>
              <Trigger Property="IsSelected" Value="True"><Setter TargetName="b" Property="Background" Value="#F2B632"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
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
            <UniformGrid Rows="1" VerticalAlignment="Center">
              <Button x:Name="ElevateBtn" Style="{StaticResource Header}" Content="Restart as admin" ToolTip="Restart this window as administrator, in the same folder (Windows asks to confirm)."/>
              <Button x:Name="SettingsBtn" Style="{StaticResource Header}" Content="Settings"/>
              <Button x:Name="SafetyBtn" Style="{StaticResource Header}" Content="Safety review" ToolTip="Test-HostBadgerSafety.ps1 reads the scripts (it runs nothing) and lists every command they use, where they write and where they may connect."/>
              <Button x:Name="UpdateCheckBtn" Style="{StaticResource Header}" Content="Check for updates"/>
            </UniformGrid>
          </StackPanel>
          <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
            <TextBlock x:Name="UpdateText" VerticalAlignment="Center" Foreground="#5F5A51" Margin="0,0,12,0" TextWrapping="Wrap" MaxWidth="520"/>
            <Button x:Name="UpdateBtn" Content="Update" Style="{StaticResource Primary}" Margin="0,0,6,0" Visibility="Collapsed"/>
            <Border x:Name="AdminPill" BorderBrush="#161513" BorderThickness="2" Padding="10,0" Height="28" VerticalAlignment="Center">
              <TextBlock x:Name="AdminText" FontWeight="Bold" FontSize="13" VerticalAlignment="Center"/>
            </Border>
          </StackPanel>
        </StackPanel>
      </DockPanel>
    </Border>

    <TabControl x:Name="Tabs" Grid.Row="1" Background="Transparent" BorderThickness="0" Padding="0,14,0,0">
    <TabItem x:Name="TabRun" Header="Analyze">
    <Grid>
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
                    <Button x:Name="CollectDirBtn" Style="{StaticResource Ghost}" Grid.Column="2" Content="Folder..." Margin="12,4,0,4"/>
                  </Grid>
                  <CheckBox x:Name="SkipAclChk" Content="Skip file permissions (faster, fewer checks)"/>
                  <CheckBox x:Name="PipesChk" Content="Read named pipe permissions (each pipe is opened for a moment; about 15 seconds)" ToolTip="Finds the named pipes of other programs that everyone can write to. Each pipe is opened for reading and closed at once; nothing is sent or read through it. Busy pipes are skipped."/>
                  <WrapPanel>
                    <TextBlock Text="Encryption" Style="{StaticResource Label}"/>
                    <RadioButton x:Name="EncNone" GroupName="Enc" Content="None" IsChecked="True"/>
                    <StackPanel Orientation="Horizontal">
                      <RadioButton x:Name="EncPass" GroupName="Enc" Content="Password" Margin="0,4,8,4"/>
                      <PasswordBox x:Name="EncPassBox" Width="160" Margin="0,4,18,4"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal">
                      <RadioButton x:Name="EncCert" GroupName="Enc" Content="Certificate" Margin="0,4,8,4"/>
                      <TextBox x:Name="EncCertBox" Width="200" Margin="0,4"/>
                      <Button x:Name="EncCertBtn" Style="{StaticResource Ghost}" Content="File..." Margin="8,4,0,4"/>
                    </StackPanel>
                  </WrapPanel>
                  <TextBlock Style="{StaticResource Muted}" Text="Certificate: the public certificate (.cer file) of whoever will open the snapshot, or the thumbprint of a certificate in this machine's store. Only the public key is used here; the snapshot opens only where the matching private key is (certificate store, or the .pfx given to the analysis)."/>
                </StackPanel>
                <RadioButton x:Name="SrcSnap" GroupName="Src" FontWeight="SemiBold" Content="Snapshots already collected: a file, or a folder with several hosts"/>
                <StackPanel x:Name="SnapPanel" Margin="26,2,0,0">
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="164"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                    <Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
                    <TextBlock Text="Snapshot file or folder" Style="{StaticResource Label}"/>
                    <TextBox x:Name="SnapshotBox" Grid.Column="1" Margin="0,4"/>
                    <StackPanel Grid.Column="2" Orientation="Horizontal" Margin="12,4,0,4">
                      <Button x:Name="SnapFileBtn" Style="{StaticResource Ghost}" Content="File..."/>
                      <Button x:Name="SnapFolderBtn" Style="{StaticResource Ghost}" Content="Folder..." Margin="0"/>
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
                  <CheckBox x:Name="PerHostChk" Content="One report per host (when the run has several hosts)" IsChecked="True" ToolTip="Besides the fleet report, one report per host. With a single host nothing more is written: it would be a copy of the report."/>
                </WrapPanel>
                <CheckBox x:Name="AcnChk" Content="NIS2: add the ACN basic measures (Italy only: Determinazione 379907/2025, D.Lgs. 138/2024)"/>
                <CheckBox x:Name="RemChk" Content="Also save a fix script for each host, with the changes chosen in the Fix tab (to run on that host; nothing is applied)" ToolTipService.ShowOnDisabled="True" Margin="0,4,18,4"/>
                <TextBlock x:Name="RemOutText" Style="{StaticResource Muted}" Margin="0,0,0,0" TextWrapping="Wrap"/>
              </StackPanel>
            </Border>

            <Border Style="{StaticResource Card}">
              <StackPanel>
                <TextBlock Text="Catalogs" Style="{StaticResource H2}"/>
                <TextBlock Style="{StaticResource Muted}" Text="HostBadger ships a copy of the drivers and extensions lists and a software lifecycle table, used offline. A download is one or a few HTTPS GETs to the address shown (nothing about the hosts is sent); it is kept next to the report and offered to the next analysis."/>
                <Grid x:Name="CatalogGrid">
                  <Grid.ColumnDefinitions><ColumnDefinition Width="230"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                </Grid>
                <CheckBox x:Name="UpdatesChk" Margin="0,8,0,0"/>
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
                  <DockPanel Grid.Row="4" Grid.Column="1">
                    <Button x:Name="ExceptionsFileBtn" Style="{StaticResource Ghost}" DockPanel.Dock="Right" Content="File..." Margin="8,4,0,4"/>
                    <TextBox x:Name="ExceptionsBox" Margin="0,4"/>
                  </DockPanel>
                  <TextBlock Grid.Row="5" Text="Policy file" Style="{StaticResource Label}" ToolTip="{Binding ToolTip, ElementName=PolicyBox}"/>
                  <DockPanel Grid.Row="5" Grid.Column="1">
                    <Button x:Name="PolicyFileBtn" Style="{StaticResource Ghost}" DockPanel.Dock="Right" Content="File..." Margin="8,4,0,4"/>
                    <TextBox x:Name="PolicyBox" Margin="0,4" ToolTip="A JSON file listing the checks your organization turns off, each with its reason (examples\policy.example.json). Those checks are not judged on any host, are left out of the score, and the report lists them with the reason."/>
                  </DockPanel>
                  <TextBlock Grid.Row="6" Text="Compare with (earlier CSV)" Style="{StaticResource Label}"/>
                  <DockPanel Grid.Row="6" Grid.Column="1">
                    <Button x:Name="CompareFileBtn" Style="{StaticResource Ghost}" DockPanel.Dock="Right" Content="File..." Margin="8,4,0,4"/>
                    <TextBox x:Name="CompareBox" Margin="0,4"/>
                  </DockPanel>
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
                <Button x:Name="RunBtn" Content="Analyze" Style="{StaticResource Primary}" ToolTipService.ShowOnDisabled="True"/>
                <Button x:Name="StopBtn" Style="{StaticResource Danger}" Content="Stop" IsEnabled="False" ToolTip="Stops the step that is running."/>
                <Button x:Name="OpenBtn" Content="Open the last report" IsEnabled="False" Margin="0"/>
              </StackPanel>
              <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
                <TextBlock Text="AI SUMMARY" FontFamily="Cascadia Mono, Consolas" FontSize="11" FontWeight="Bold" Foreground="#5F5A51" VerticalAlignment="Center" Margin="0,0,10,0"/>
                <Button x:Name="AiDryBtn" Content="AI: dry run"/>
                <Button x:Name="AiSendBtn" Content="AI: send to Gemini" Margin="0" ToolTipService.ShowOnDisabled="True"/>
              </StackPanel>
            </DockPanel>
            <DockPanel Margin="0,8,0,0">
              <Button x:Name="AiPickBtn" Style="{StaticResource Ghost}" DockPanel.Dock="Right" Content="Other report..." Margin="8,0,0,0" VerticalAlignment="Center"/>
              <TextBlock x:Name="AiTargetText" Foreground="#5F5A51" VerticalAlignment="Center" TextWrapping="Wrap"/>
            </DockPanel>
            <DockPanel LastChildFill="False" Margin="0,10,0,0">
              <StackPanel DockPanel.Dock="Left" Orientation="Horizontal" VerticalAlignment="Center">
                <ProgressBar x:Name="Busy" Width="120" Height="10" IsIndeterminate="False" Visibility="Hidden" Margin="0,0,10,0" Foreground="#E2372A" Background="#E8E2D4" BorderBrush="#161513"/>
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
    </TabItem>

    <!-- Fix: what the fix scripts change, and Fix this machine. The log on the right repeats the one of Analyze. -->
    <TabItem x:Name="TabFix" Header="Fix">
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*" MinWidth="560"/>
        <ColumnDefinition Width="10"/>
        <ColumnDefinition Width="440" MinWidth="300"/>
      </Grid.ColumnDefinitions>
      <Grid Grid.Column="0">
        <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
        <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="0,0,8,0">
          <StackPanel>            <Border Style="{StaticResource Card}">
              <StackPanel>
                <TextBlock Text="Fix" Style="{StaticResource H2}"/>
                <Border Style="{StaticResource Callout}">
                  <StackPanel>
                    <TextBlock Text="This button changes this machine" FontWeight="Bold" Foreground="#B3261E" Margin="0,0,0,4"/>
                    <TextBlock x:Name="RemWarn" TextWrapping="Wrap" LineHeight="20"/>
                  </StackPanel>
                </Border>
                <StackPanel x:Name="RemPanel" Margin="0,4,0,0">
                  <TextBlock Text="What the fixes change" Style="{StaticResource H3}" Margin="0,4,0,4"/>
                  <StackPanel x:Name="ProfilePanel"/>
                  <TextBlock Text="Also" Style="{StaticResource H3}"/>
                  <CheckBox x:Name="DebloatChk" Content="Debloat: preinstalled Store apps (workstations), unused consumer services and Windows components (Xbox, Fax, Steps Recorder...). Strict includes it"/>
                  <CheckBox x:Name="PrivacyChk" Content="Disable telemetry: the privacy and telemetry settings of every level (Strict includes them)"/>
                </StackPanel>
              </StackPanel>
            </Border>
          </StackPanel>
        </ScrollViewer>
        <Border Grid.Row="1" Style="{StaticResource Card}" Padding="14,12" Margin="0,0,8,0">
          <StackPanel>
            <Border x:Name="ApplyPanel" Style="{StaticResource Callout}" Visibility="Collapsed" Margin="0,0,0,12">
              <StackPanel>
                <TextBlock x:Name="ApplyHead" FontWeight="Bold" Foreground="#B3261E" Margin="0,0,0,4"/>
                <TextBlock x:Name="ApplyText" TextWrapping="Wrap" LineHeight="20" Foreground="#3A1714"/>
                <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
                  <Button x:Name="ApplyYesBtn" Content="Apply them" Style="{StaticResource Danger}"/>
                  <Button x:Name="ApplyNoBtn" Content="Don't apply" Style="{StaticResource Ghost}" Margin="0"/>
                </StackPanel>
              </StackPanel>
            </Border>
            <StackPanel Orientation="Horizontal">
              <Button x:Name="FixBtn" Content="Fix this machine" Style="{StaticResource Danger}" ToolTipService.ShowOnDisabled="True"/>
              <Button x:Name="FixStopBtn" Style="{StaticResource Danger}" Content="Stop" IsEnabled="False" ToolTip="Stops the step that is running." Margin="0"/>
            </StackPanel>
            <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="0,10,0,0">
              <ProgressBar x:Name="FixBusy" Width="120" Height="10" IsIndeterminate="False" Visibility="Hidden" Margin="0,0,10,0" Foreground="#E2372A" Background="#E8E2D4" BorderBrush="#161513"/>
              <TextBlock x:Name="FixStatusText" Foreground="#5F5A51"/>
            </StackPanel>
          </StackPanel>
        </Border>
      </Grid>
      <GridSplitter Grid.Column="1" Width="10" HorizontalAlignment="Stretch" Background="Transparent" Cursor="SizeWE"/>
      <Border Grid.Column="2" BorderBrush="#161513" BorderThickness="3" Background="#161513" Margin="0,0,6,0">
        <Grid>
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <TextBlock Text="LOG" Foreground="#F2B632" FontWeight="Bold" FontFamily="Cascadia Mono, Consolas" Margin="10,6,10,0"/>
          <TextBox x:Name="FixLogBox" Grid.Row="1" IsReadOnly="True" Background="#161513" Foreground="#F3EFE6" BorderThickness="0" FontFamily="Cascadia Mono, Consolas" FontSize="12"
                   VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" TextWrapping="Wrap" Padding="10,6,10,10"/>
        </Grid>
      </Border>
    </Grid>
    </TabItem>

    <!-- Results: the findings of the report (its CSV), by category, with filters and the details of one -->
    <TabItem x:Name="TabResults" Header="Results">
      <Grid>
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
        <Border Style="{StaticResource Card}" Padding="16,12">
          <StackPanel>
            <DockPanel>
              <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                <Button x:Name="ResOpenBtn" Content="Open the HTML report" IsEnabled="False"/>
                <Button x:Name="ResPickBtn" Style="{StaticResource Ghost}" Content="Other report..." Margin="0"/>
              </StackPanel>
              <Border x:Name="ScoreBadge" DockPanel.Dock="Left" BorderBrush="#161513" BorderThickness="3" Background="#E8E2D4" Width="96" Margin="0,0,16,0" Padding="4,2" Visibility="Collapsed" Effect="{StaticResource HardSm}">
                <StackPanel HorizontalAlignment="Center" VerticalAlignment="Center">
                  <TextBlock x:Name="ScoreNum" FontFamily="Bahnschrift, Segoe UI" FontSize="30" FontWeight="Bold" HorizontalAlignment="Center"/>
                  <TextBlock x:Name="ScoreLbl" FontSize="11" FontWeight="Bold" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap"/>
                </StackPanel>
              </Border>
              <StackPanel VerticalAlignment="Center" Margin="0,0,12,0">
                <TextBlock x:Name="ResTitle" Text="No report yet" FontFamily="Bahnschrift, Segoe UI" FontSize="20" FontWeight="Bold" TextTrimming="CharacterEllipsis"/>
                <TextBlock x:Name="ResSub" Foreground="#5F5A51" TextWrapping="Wrap"/>
              </StackPanel>
            </DockPanel>
            <WrapPanel Margin="0,10,0,0">
              <StackPanel x:Name="ResHostPanel" Orientation="Horizontal" Margin="0,0,18,0">
                <TextBlock Text="Host" Style="{StaticResource Label}"/>
                <ComboBox x:Name="ResHost" MinWidth="200" Margin="0,4"/>
              </StackPanel>
              <TextBlock Text="Search" Style="{StaticResource Label}"/>
              <TextBox x:Name="ResSearch" Width="240" Margin="0,4,18,4" ToolTip="Words of the title, object, detail, check name or rule (Ctrl+F). Every word must match."/>
              <StackPanel x:Name="ResSevPanel" Orientation="Horizontal" Margin="0,0,8,0"/>
              <CheckBox x:Name="ResCisChk" Content="CIS-based" IsChecked="True" ToolTip="The findings that quote a CIS benchmark rule"/>
              <CheckBox x:Name="ResStigChk" Content="DISA STIG" IsChecked="True" ToolTip="The DISA STIG rules (there can be hundreds per host)"/>
            </WrapPanel>
          </StackPanel>
        </Border>
        <Grid Grid.Row="1">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="250" MinWidth="180"/>
            <ColumnDefinition Width="*" MinWidth="360"/>
            <ColumnDefinition Width="10"/>
            <ColumnDefinition Width="430" MinWidth="260"/>
          </Grid.ColumnDefinitions>
          <Border Style="{StaticResource Flat}" Margin="0,0,14,6">
            <DockPanel>
              <TextBlock DockPanel.Dock="Top" Text="Categories" Style="{StaticResource H3}" Margin="12,8,0,6"/>
              <ListBox x:Name="ResCats" BorderThickness="0" Background="Transparent" ScrollViewer.HorizontalScrollBarVisibility="Disabled" Padding="4,0,4,6">
                <ListBox.ItemContainerStyle>
                  <Style TargetType="ListBoxItem">
                    <Setter Property="Padding" Value="8,5"/>
                    <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
                    <Setter Property="Cursor" Value="Hand"/>
                    <Setter Property="Template">
                      <Setter.Value>
                        <ControlTemplate TargetType="ListBoxItem">
                          <Border x:Name="b" Background="Transparent" BorderBrush="Transparent" BorderThickness="2" Padding="{TemplateBinding Padding}">
                            <ContentPresenter/>
                          </Border>
                          <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#FBE7B5"/></Trigger>
                            <Trigger Property="IsSelected" Value="True"><Setter TargetName="b" Property="Background" Value="#F2B632"/><Setter TargetName="b" Property="BorderBrush" Value="#161513"/></Trigger>
                          </ControlTemplate.Triggers>
                        </ControlTemplate>
                      </Setter.Value>
                    </Setter>
                  </Style>
                </ListBox.ItemContainerStyle>
              </ListBox>
            </DockPanel>
          </Border>
          <DataGrid x:Name="ResGrid" Grid.Column="1" Margin="0,0,0,6" AutoGenerateColumns="False" IsReadOnly="True" SelectionMode="Single"
                    HeadersVisibility="Column" GridLinesVisibility="Horizontal" HorizontalGridLinesBrush="#E8E2D4" RowHeaderWidth="0"
                    Background="#FFFDF8" RowBackground="#FFFDF8" AlternatingRowBackground="#F8F4EC" BorderBrush="#161513" BorderThickness="3"
                    CanUserResizeRows="False" CanUserAddRows="False" EnableRowVirtualization="True" VirtualizingPanel.VirtualizationMode="Recycling">
            <DataGrid.ColumnHeaderStyle>
              <Style TargetType="DataGridColumnHeader">
                <Setter Property="Background" Value="#161513"/>
                <Setter Property="Foreground" Value="#F3EFE6"/>
                <Setter Property="FontWeight" Value="Bold"/>
                <Setter Property="Padding" Value="8,6"/>
                <Setter Property="BorderBrush" Value="#5F5A51"/>
                <Setter Property="BorderThickness" Value="0,0,1,0"/>
              </Style>
            </DataGrid.ColumnHeaderStyle>
            <DataGrid.CellStyle>
              <Style TargetType="DataGridCell">
                <Setter Property="BorderThickness" Value="0"/>
                <Setter Property="Padding" Value="6,4"/>
                <Setter Property="Template">
                  <Setter.Value>
                    <ControlTemplate TargetType="DataGridCell">
                      <Border Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}"><ContentPresenter VerticalAlignment="Center"/></Border>
                    </ControlTemplate>
                  </Setter.Value>
                </Setter>
                <Style.Triggers>
                  <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#FBE7B5"/>
                    <Setter Property="Foreground" Value="#161513"/>
                  </Trigger>
                </Style.Triggers>
              </Style>
            </DataGrid.CellStyle>
            <DataGrid.Columns>
              <DataGridTemplateColumn Header="Severity" Width="98" SortMemberPath="Rank">
                <DataGridTemplateColumn.CellTemplate>
                  <DataTemplate>
                    <Border x:Name="pill" BorderBrush="#161513" BorderThickness="2" Padding="6,0" HorizontalAlignment="Left" Background="#E8E2D4">
                      <TextBlock x:Name="pillText" Text="{Binding Severity}" FontWeight="Bold" FontSize="12"/>
                    </Border>
                    <DataTemplate.Triggers>
                      <DataTrigger Binding="{Binding Severity}" Value="Critical"><Setter TargetName="pill" Property="Background" Value="#E2372A"/><Setter TargetName="pillText" Property="Foreground" Value="#FFFDF8"/></DataTrigger>
                      <DataTrigger Binding="{Binding Severity}" Value="High"><Setter TargetName="pill" Property="Background" Value="#FBD9D2"/></DataTrigger>
                      <DataTrigger Binding="{Binding Severity}" Value="Medium"><Setter TargetName="pill" Property="Background" Value="#F2B632"/></DataTrigger>
                    </DataTemplate.Triggers>
                  </DataTemplate>
                </DataGridTemplateColumn.CellTemplate>
              </DataGridTemplateColumn>
              <DataGridTextColumn Header="Finding" Binding="{Binding Title}" Width="3*">
                <DataGridTextColumn.ElementStyle><Style TargetType="TextBlock"><Setter Property="TextTrimming" Value="CharacterEllipsis"/><Setter Property="FontWeight" Value="SemiBold"/></Style></DataGridTextColumn.ElementStyle>
              </DataGridTextColumn>
              <DataGridTextColumn Header="Object" Binding="{Binding Object}" Width="2*">
                <DataGridTextColumn.ElementStyle><Style TargetType="TextBlock"><Setter Property="TextTrimming" Value="CharacterEllipsis"/></Style></DataGridTextColumn.ElementStyle>
              </DataGridTextColumn>
              <DataGridTextColumn Header="Host" Binding="{Binding Host}" Width="Auto"/>
              <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="Auto"/>
            </DataGrid.Columns>
          </DataGrid>
          <Border x:Name="ResOverviewBox" Grid.Column="1" Grid.ColumnSpan="3" Style="{StaticResource Flat}" Margin="0,0,6,6" Visibility="Collapsed">
            <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" Padding="20,14">
              <StackPanel x:Name="ResOverview"/>
            </ScrollViewer>
          </Border>
          <TextBlock x:Name="ResEmpty" Grid.Column="1" Margin="24,60,24,0" TextWrapping="Wrap" Foreground="#5F5A51" FontSize="15" HorizontalAlignment="Center" TextAlignment="Center"/>
          <GridSplitter x:Name="ResSplit" Grid.Column="2" Width="10" HorizontalAlignment="Stretch" Background="Transparent" Cursor="SizeWE"/>
          <Border x:Name="ResDetailBox" Grid.Column="3" Style="{StaticResource Flat}" Margin="0,0,6,6">
            <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="16,12">
              <StackPanel x:Name="ResDetail"/>
            </ScrollViewer>
          </Border>
        </Grid>
      </Grid>
    </TabItem>
    </TabControl>
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
            <CheckBox x:Name="SetAiOffer" Content="Ask about the AI summary after each analysis"/>
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
              <RadioButton x:Name="SetEncAsk" GroupName="SetEnc" Content="Ask (guided menu)" IsChecked="True"/>
              <RadioButton x:Name="SetEncNone" GroupName="SetEnc" Content="None"/>
              <RadioButton x:Name="SetEncPass" GroupName="SetEnc" Content="Password (typed each time)"/>
              <RadioButton x:Name="SetEncCert" GroupName="SetEnc" Content="Certificate" Margin="0,4,8,4"/>
              <TextBox x:Name="SetCert" Width="240" Margin="0,4" ToolTip="Path of the .cer file (public certificate) of whoever opens the snapshots, or the thumbprint of a certificate in the store."/>
            </StackPanel>
          </StackPanel>
        </Border>

        <Border Style="{StaticResource Card}">
          <StackPanel>
            <TextBlock Text="Updates" Style="{StaticResource H2}"/>
            <CheckBox x:Name="SetAutoUpdate" Content="Check for updates each time the window opens"/>
            <TextBlock Style="{StaticResource Muted}" Text="It asks GitHub at every start, like the Check for updates button: git fetch origin in a git clone, otherwise one GET from raw.githubusercontent.com. Nothing is installed without you."/>
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
    Add-LogText "$Text`r`n"
}
function Add-LogText {
    # The log of Analyze, repeated in the Fix tab.
    param([string]$Text)
    foreach ($box in $ui.LogBox, $ui.FixLogBox) { $box.AppendText($Text); $box.ScrollToEnd() }
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
function Get-PasswordSnapshots {
    # The .hbx files that need a password: "HBX1" then mode 1. Mode 2 (certificate) is opened with the
    # private key of the certificate store, no password.
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    $files = if ((Get-Item -LiteralPath $Path).PSIsContainer) { @(Get-ChildItem -LiteralPath $Path -Recurse -File -Filter 'hostsnapshot_*.hbx' -ErrorAction SilentlyContinue) } else { @(Get-Item -LiteralPath $Path | Where-Object { $_.Extension -eq '.hbx' }) }
    foreach ($f in $files) {
        try {
            $fs = [System.IO.File]::OpenRead($f.FullName)
            try { $head = New-Object byte[] 5; $n = $fs.Read($head, 0, 5) } finally { $fs.Dispose() }
            if ($n -eq 5 -and [Text.Encoding]::ASCII.GetString($head, 0, 4) -eq 'HBX1' -and $head[4] -eq 1) { $f }
        }
        catch { }
    }
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
# A relative path of the form resolves where the window works, not in the folder of the process.
[void]$script:Rs.SessionStateProxy.Path.SetLocation($PWD.ProviderPath)
# The step a script is at (Step-Spinner writes it, the timer shows it: Downloading..., Analyzing...).
$script:TaskStatus = [hashtable]::Synchronized(@{ Text = '' })
$script:Rs.SessionStateProxy.SetVariable('HostBadgerStatus', $script:TaskStatus)
$script:Task = $null
$script:Stopping = $false
$script:LastReport = ''
$script:LastSnapshot = ''
$script:Kept = $false
# The report was picked with "Other report...": the AI buttons do not ask which one again.
$script:ReportChosen = $false
$script:ApplyAfter = $false
$script:ForFix = $false
# This machine's last collection in this window (time and options) and the analysis that wrote its fix
# script: Fix this machine reuses them for $script:FixReuseMinutes instead of collecting again.
$script:LastSnapshotAt = $null
$script:LastSnapshotOpts = ''
$script:FixBasis = $null
$script:FixReuseMinutes = 30

function Set-Busy {
    param([bool]$On, [string]$Text = '')
    $ui.Busy.IsIndeterminate = $On; $ui.FixBusy.IsIndeterminate = $On
    # The bars show only while something runs: an empty bar at rest looks like a stalled one.
    $vis = if ($On) { 'Visible' } else { 'Hidden' }; $ui.Busy.Visibility = $vis; $ui.FixBusy.Visibility = $vis
    $ui.StatusText.Text = $Text; $ui.FixStatusText.Text = $Text
    foreach ($b in 'UpdateCheckBtn', 'UpdateBtn', 'ElevateBtn', 'SettingsBtn', 'SafetyBtn') { $ui[$b].IsEnabled = -not $On }
    foreach ($b in 'AiDryBtn', 'AiPickBtn', 'ResPickBtn') { $ui[$b].IsEnabled = -not $On }
    Update-Actions
    if (-not $On) { Update-AiTarget }
}

function Start-GuiTask {
    # Work: a script block run in the background runspace (as text, so it belongs to that runspace).
    # Its text output goes to the log; objects with a Kind go to Done.
    param([string]$Label, [scriptblock]$Work, [object[]]$Arguments, [scriptblock]$Done)
    if ($script:Task) { return }
    if ($script:ApplyPending) { Show-ApplyPanel $false; Add-Log 'Fix: not applied, nothing changed.' }
    $ps = [powershell]::Create()
    $ps.Runspace = $script:Rs
    [void]$ps.AddScript($Work.ToString())
    foreach ($a in $Arguments) { [void]$ps.AddArgument($a) }
    $in = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
    $in.Complete()
    $out = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
    $handle = $ps.BeginInvoke($in, $out)
    $script:TaskStatus['Text'] = ''
    $script:Stopping = $false
    $script:Task = @{ Label = $Label; Ps = $ps; Handle = $handle; Out = $out; Seen = 0; ErrSeen = 0; Done = $Done; Status = ''; Results = (New-Object System.Collections.Generic.List[object]); Lines = (New-Object System.Collections.Generic.List[string]) }
    Add-Log ''
    Add-Log "--- $Label ---"
    Set-Busy $true $Label
    $script:Timer.Start()
}

function Read-TaskOutput {
    # What the task printed since the last tick, added to the log in one go (one line at a time redraws
    # the log for each line: a STIG analysis prints thousands).
    param($T)
    $sb = New-Object System.Text.StringBuilder
    while ($T.Seen -lt $T.Out.Count) {
        $o = $T.Out[$T.Seen]; $T.Seen++
        if ($o -and $o.PSObject.Properties['Kind']) { $T.Results.Add($o) } else { $line = "$o"; $T.Lines.Add($line); [void]$sb.Append($line).Append("`r`n") }
    }
    $errs = $T.Ps.Streams.Error
    while ($T.ErrSeen -lt $errs.Count) { [void]$sb.Append("ERROR: $($errs[$T.ErrSeen])`r`n"); $T.ErrSeen++ }
    if ($sb.Length) { Add-LogText $sb.ToString() }
}
function Read-GuiTask {
    $t = $script:Task
    if (-not $t) { return }
    Read-TaskOutput $t
    $st = "$($script:TaskStatus['Text'])"
    if ($st -and $st -ne $t.Status -and -not $script:Stopping) { $t.Status = $st; $ui.StatusText.Text = $st; $ui.FixStatusText.Text = $st }
    if (-not $t.Handle.IsCompleted) { return }
    $script:Timer.Stop()
    try { [void]$t.Ps.EndInvoke($t.Handle) } catch { Add-Log "Stopped: $($_.Exception.Message)" }
    Read-TaskOutput $t
    $t.Ps.Dispose()
    $script:Task = $null
    # Stopped: what would have followed (the analysis after a collection, the fix preview) does not run.
    if ($script:Stopping) { $script:Stopping = $false; Add-Log "--- $($t.Label): stopped ---"; Set-Busy $false 'Stopped'; Update-Outputs; return }
    Set-Busy $false 'Ready'
    if ($t.Done) { & $t.Done $t }
}
function Stop-GuiTask {
    # Stops the running step without waiting (BeginStop): the timer then sees it end. HostBadger.ps1
    # closes its run log in its finally block.
    $t = $script:Task
    if (-not $t -or $script:Stopping) { return }
    if ($t.Label -like 'Applying*') {
        $warn = "The fixes are being applied: stopping now leaves only part of them (the rollback file holds what was already changed).`n`nStop anyway?"
        if ("$([System.Windows.MessageBox]::Show($warn, 'HostBadger', 'YesNo', 'Warning', 'No'))" -ne 'Yes') { return }
    }
    $script:Stopping = $true
    $ui.StatusText.Text = 'Stopping...'; $ui.FixStatusText.Text = 'Stopping...'
    Update-Actions
    try { [void]$t.Ps.BeginStop($null, $null) } catch { Add-Log "Not stopped: $($_.Exception.Message)" }
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
# The fix script of debloat and telemetry alone (no fix of the findings): it needs the role of this
# machine, not a snapshot. The libraries load into a module of their own, so nothing they define stays
# in the runspace the analyses run in.
$script:ProfileFixWork = {
    param([string]$Root, [string]$OutDir, [hashtable]$Opt)
    $mod = New-Object System.Management.Automation.PSModuleInfo $true
    & $mod {
        param([string]$Root, [string]$OutDir, [hashtable]$Opt)
        . (Join-Path $Root 'lib\Common.ps1')
        . (Join-Path $Root 'lib\Checks.ps1')
        . (Join-Path $Root 'lib\Remediation.ps1')
        $pt = "$((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -Name ProductType -ErrorAction SilentlyContinue).ProductType)"
        $role = switch ($pt) { 'LanmanNT' { 'dc' } 'ServerNT' { 'server' } default { 'workstation' } }
        $ver = if ([System.IO.File]::ReadAllText((Join-Path $Root 'HostBadger.ps1')) -match "\`$script:HostBadgerVersion = '([\d.]+)'") { $Matches[1] } else { '?' }
        $r = Write-ProfileOnlyScript -HostName $env:COMPUTERNAME -Role $role -OutDir $OutDir -ToolVersion $ver -Debloat:$Opt.Debloat -Privacy:$Opt.Privacy
        if (-not $r.File) { "Nothing to write for a $role."; return }
        "Fix script: $($r.File) ($($r.Actions) setting(s) for a $role)"
        [pscustomobject]@{ Kind = 'profilefix'; File = $r.File }
    } $Root $OutDir $Opt
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
        Add-OutputLink 'Score history' (Join-Path (Split-Path -Parent $r) 'hostbadger-history.csv')
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

# ---------------- Results: the findings of a report, from the CSV the analysis writes next to it.
$script:SevOrder = @('Critical', 'High', 'Medium', 'Low')
$script:SevRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
$script:SevColors = @{ Critical = '#E2372A'; High = '#FBD9D2'; Medium = '#F2B632'; Low = '#E8E2D4' }
$script:Res = $null
$script:ResBusy = $false
$script:ResSevBoxes = @{}
$script:CheckInfo = $null

function Get-CheckInfo {
    # Description and remediation of each check, read from $script:CheckCatalog of lib\Checks.ps1 with the
    # parser (nothing of that file runs here). Read once, the first time a finding is shown.
    if ($null -ne $script:CheckInfo) { return $script:CheckInfo }
    $info = @{}
    try {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'lib\Checks.ps1'), [ref]$null, [ref]$null)
        $asg = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$script:CheckCatalog' }, $false)
        $table = $asg.Right.Find({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)
        foreach ($kv in $table.KeyValuePairs) {
            $entry = $kv.Item2.Find({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)
            if (-not $entry) { continue }
            $e = @{}
            foreach ($p in $entry.KeyValuePairs) {
                $k = $p.Item1.Extent.Text
                if ($k -notin 'Description', 'Remediation') { continue }
                $s = $p.Item2.Find({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)
                if ($s) { $e[$k] = $s.Value }
            }
            $info[($kv.Item1.Extent.Text -replace "^['`"]|['`"]$", '')] = $e
        }
    }
    catch { Add-Log "The descriptions of the checks were not read: $($_.Exception.Message)" }
    $script:CheckInfo = $info
    return $info
}

function Initialize-Results {
    # One box per severity, with its colour and the number of findings the other filters leave.
    foreach ($s in $script:SevOrder) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.IsChecked = $true; $cb.Margin = '0,4,10,4'; $cb.Tag = $s
        $sp = New-Object System.Windows.Controls.StackPanel; $sp.Orientation = 'Horizontal'
        $pill = New-Object System.Windows.Controls.Border
        $pill.Background = New-Brush $script:SevColors[$s]; $pill.BorderBrush = New-Brush '#161513'; $pill.BorderThickness = '2'; $pill.Padding = '6,0'
        $pt = New-Object System.Windows.Controls.TextBlock; $pt.Text = $s; $pt.FontWeight = 'Bold'; $pt.FontSize = 12
        if ($s -eq 'Critical') { $pt.Foreground = New-Brush '#FFFDF8' }
        $pill.Child = $pt
        $count = New-Object System.Windows.Controls.TextBlock; $count.Margin = '6,0,0,0'; $count.VerticalAlignment = 'Center'; $count.FontWeight = 'SemiBold'
        [void]$sp.Children.Add($pill); [void]$sp.Children.Add($count)
        $cb.Content = $sp
        $cb.Add_Click({ Update-ResultsView })
        [void]$ui.ResSevPanel.Children.Add($cb)
        $script:ResSevBoxes[$s] = @{ Box = $cb; Count = $count }
    }
    Show-ResultDetail $null
    Update-ResultsView
}

function Show-Results {
    # The Results tab shows the findings of this report; a report already loaded is read again only
    # when its CSV changed.
    param([string]$Report)
    $csv = if ($Report) { $Report -replace '(?i)\.html?$', '.csv' } else { '' }
    $stamp = if ($csv -and $csv -ne $Report -and (Test-Path -LiteralPath $csv)) { (Get-Item -LiteralPath $csv).LastWriteTimeUtc.Ticks } else { 0 }
    # The AI step rewrites the HTML only: its time counts too.
    $htmlStamp = if ($Report -and (Test-Path -LiteralPath $Report)) { (Get-Item -LiteralPath $Report).LastWriteTimeUtc.Ticks } else { 0 }
    if ($script:Res -and $script:Res.Path -eq $Report -and $script:Res.Stamp -eq $stamp -and $script:Res.HtmlStamp -eq $htmlStamp) { return }
    $ui.ResOpenBtn.IsEnabled = [bool]$htmlStamp
    # The figures of the report (score, coverage, frameworks...): a JSON block at the end of the HTML.
    $summary = $null
    if ($htmlStamp) {
        try {
            $html = [System.IO.File]::ReadAllText($Report)
            $mark = '<script type="application/json" id="hostbadger-summary">'
            $i = $html.LastIndexOf($mark)
            if ($i -ge 0) { $start = $i + $mark.Length; $end = $html.IndexOf('</script>', $start); if ($end -gt $start) { $summary = $html.Substring($start, $end - $start) | ConvertFrom-Json } }
        }
        catch { Add-Log "Results: the overview of $Report was not read: $($_.Exception.Message)" }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    if ($stamp) {
        try {
            foreach ($r in @(Import-Csv -LiteralPath $csv)) {
                $text = "$($r.Title) $($r.Object) $($r.Detail) $($r.Type) $($r.Cis) $($r.Category) $($r.Host) $($r.Mitre)".ToLowerInvariant()
                $rows.Add([pscustomobject]@{
                        Severity = "$($r.Severity)"; Rank = [int]$script:SevRank["$($r.Severity)"]; Title = "$($r.Title)"; Category = "$($r.Category)"; Host = "$($r.Host)"
                        Object = "$($r.Object)"; Detail = "$($r.Detail)"; Type = "$($r.Type)"; Mitre = "$($r.Mitre)"; Cis = "$($r.Cis)"; CisBenchmark = "$($r.CisBenchmark)"
                        Found = "$($r.Found)"; Expected = "$($r.Expected)"; Attacks = "$($r.Attacks)"; Stig = ("$($r.Category)" -eq 'DISA STIG'); Text = $text
                    })
            }
        }
        catch { Add-Log "Results: $csv not read: $($_.Exception.Message)"; $stamp = 0 }
    }
    $sorted = @($rows | Sort-Object @{ Expression = 'Rank'; Descending = $true }, Category, Title, Host, Object)
    $perHost = @{}
    foreach ($f in $sorted) { $perHost[$f.Host] = 1 + [int]$perHost[$f.Host] }
    $hosts = @($perHost.Keys | Sort-Object)
    $script:Res = @{ Path = $Report; Stamp = $stamp; HtmlStamp = $htmlStamp; Rows = $sorted; Hosts = $hosts; Summary = $summary }

    $ui.ResTitle.Text = if ($Report) { Split-Path -Leaf $Report } else { 'No report yet' }
    $ui.ResSub.Text = if (-not $Report) { 'Analyze something (tab Analyze), or choose an earlier report with Other report...' }
    elseif (-not $stamp) { 'No findings CSV next to this report (a per-host report has none): choose the report of the run.' }
    elseif ($summary) { "$($sorted.Count) finding(s) on $($hosts.Count) host(s), report of $((Get-Item -LiteralPath $csv).LastWriteTime.ToString('yyyy-MM-dd HH:mm')). Overview: scores, coverage, frameworks, exceptions, comparison, fixes and AI summary; the categories list the findings." }
    else { "$($sorted.Count) finding(s) on $($hosts.Count) host(s), report of $((Get-Item -LiteralPath $csv).LastWriteTime.ToString('yyyy-MM-dd HH:mm')). This report was written by an earlier HostBadger: analyze again for the overview, or open the HTML report." }
    $ui.TabResults.Header = if ($stamp) { "Results ($($sorted.Count))" } else { 'Results' }

    # Filters: every host, and the CIS and STIG findings as the report shows them.
    $script:ResBusy = $true
    try {
        $ui.ResHost.Items.Clear()
        $all = New-Object System.Windows.Controls.ComboBoxItem; $all.Content = "All hosts ($($hosts.Count))"; $all.Tag = ''
        [void]$ui.ResHost.Items.Add($all)
        foreach ($h in $hosts) {
            $ci = New-Object System.Windows.Controls.ComboBoxItem; $ci.Content = "$h ($($perHost[$h]))"; $ci.Tag = $h
            [void]$ui.ResHost.Items.Add($ci)
        }
        $ui.ResHost.SelectedIndex = 0
        $ui.ResHostPanel.Visibility = if ($hosts.Count -gt 1) { 'Visible' } else { 'Collapsed' }
        $ui.ResGrid.Columns[3].Visibility = if ($hosts.Count -gt 1) { 'Visible' } else { 'Collapsed' }
        $ui.ResSearch.Text = ''
        $ui.ResCisChk.IsChecked = [bool]$ui.ShowCisChk.IsChecked
        $ui.ResStigChk.IsChecked = [bool]($ui.StigChk.IsChecked -and $ui.ShowStigChk.IsChecked)
        $ui.ResCats.SelectedIndex = -1
        $ui.ResGrid.Items.SortDescriptions.Clear()
    }
    finally { $script:ResBusy = $false }
    # A new report opens on its overview.
    $script:ResStartCat = '#overview'
    Update-ResultsView
}

function New-CategoryItem {
    # A category of the list: a square of the colour of its worst finding, the name, the count.
    param([string]$Name, [string]$Tag, [string]$Count, [string]$Worst)
    $item = New-Object System.Windows.Controls.ListBoxItem
    $item.Tag = $Tag
    $dp = New-Object System.Windows.Controls.DockPanel
    $n = New-Object System.Windows.Controls.TextBlock; $n.Text = $Count; $n.FontWeight = 'Bold'; $n.Margin = '8,0,0,0'
    [System.Windows.Controls.DockPanel]::SetDock($n, 'Right')
    $sq = New-Object System.Windows.Controls.Border; $sq.Width = 12; $sq.Height = 12; $sq.Margin = '0,0,8,0'; $sq.BorderBrush = New-Brush '#161513'; $sq.BorderThickness = '2'
    $sq.Background = if ($Worst) { New-Brush $script:SevColors[$Worst] } else { New-Brush '#FFFDF8' }
    [System.Windows.Controls.DockPanel]::SetDock($sq, 'Left')
    $t = New-Object System.Windows.Controls.TextBlock; $t.Text = $Name; $t.TextTrimming = 'CharacterEllipsis'
    if (-not $Tag -or $Tag -like '#*') { $t.FontWeight = 'Bold' }
    [void]$dp.Children.Add($n); [void]$dp.Children.Add($sq); [void]$dp.Children.Add($t)
    $item.Content = $dp
    return $item
}

function Update-ResultsView {
    # Host, search, CIS/STIG and severity filters, then the categories (counted after those filters),
    # then the table. The sort and the selected finding are kept when they still apply.
    if ($script:ResBusy) { return }
    $rows = if ($script:Res) { $script:Res.Rows } else { @() }
    $hostSel = if ($ui.ResHost.SelectedItem) { "$($ui.ResHost.SelectedItem.Tag)" } else { '' }
    $words = @("$($ui.ResSearch.Text)".ToLowerInvariant() -split '\s+' | Where-Object { $_ })
    $cis = [bool]$ui.ResCisChk.IsChecked; $stig = [bool]$ui.ResStigChk.IsChecked
    $base = New-Object System.Collections.Generic.List[object]
    foreach ($f in $rows) {
        if ($hostSel -and $f.Host -ne $hostSel) { continue }
        if ($f.Stig) { if (-not $stig) { continue } } elseif ($f.Cis -and -not $cis) { continue }
        $miss = $false
        foreach ($w in $words) { if ($f.Text.IndexOf($w) -lt 0) { $miss = $true; break } }
        if (-not $miss) { $base.Add($f) }
    }
    $sevCount = @{}; $sevOn = @{}
    foreach ($s in $script:SevOrder) { $sevCount[$s] = 0; $sevOn[$s] = [bool]$script:ResSevBoxes[$s].Box.IsChecked }
    foreach ($f in $base) { if ($sevCount.ContainsKey($f.Severity)) { $sevCount[$f.Severity]++ } }
    foreach ($s in $script:SevOrder) { $script:ResSevBoxes[$s].Count.Text = "$($sevCount[$s])" }
    $bySev = New-Object System.Collections.Generic.List[object]
    foreach ($f in $base) { if ($sevOn[$f.Severity] -ne $false) { $bySev.Add($f) } }

    # Categories: alphabetical, DISA STIG (compliance with a baseline) last.
    $cats = @{}
    foreach ($f in $bySev) {
        $c = $cats[$f.Category]
        if (-not $c) { $c = @{ Count = 0; Rank = 0; Worst = '' }; $cats[$f.Category] = $c }
        $c.Count++
        if ($f.Rank -gt $c.Rank) { $c.Rank = $f.Rank; $c.Worst = $f.Severity }
    }
    $catSel = if ($script:ResStartCat) { $script:ResStartCat } elseif ($ui.ResCats.SelectedItem) { "$($ui.ResCats.SelectedItem.Tag)" } else { '' }
    $script:ResStartCat = ''
    $overview = $catSel -eq '#overview'
    if ($catSel -and -not $overview -and -not $cats.ContainsKey($catSel)) { $catSel = '' }
    $worstAll = ''; $worstRank = 0
    foreach ($c in $cats.Values) { if ($c.Rank -gt $worstRank) { $worstRank = $c.Rank; $worstAll = $c.Worst } }
    $script:ResBusy = $true
    try {
        $ui.ResCats.Items.Clear()
        if ($script:Res -and $script:Res.Stamp) {
            $score = Get-ScoreFor $hostSel
            [void]$ui.ResCats.Items.Add((New-CategoryItem -Name 'Overview' -Tag '#overview' -Count $(if ($score) { "$($score.Score) $($score.Grade)" } else { '' }) -Worst ''))
        }
        [void]$ui.ResCats.Items.Add((New-CategoryItem -Name 'All findings' -Tag '' -Count "$($bySev.Count)" -Worst $worstAll))
        foreach ($name in @($cats.Keys | Sort-Object @{ Expression = { $_ -eq 'DISA STIG' } }, @{ Expression = { $_ } })) {
            [void]$ui.ResCats.Items.Add((New-CategoryItem -Name $name -Tag $name -Count "$($cats[$name].Count)" -Worst $cats[$name].Worst))
        }
        $ui.ResCats.SelectedItem = @($ui.ResCats.Items | Where-Object { "$($_.Tag)" -eq $catSel })[0]
        if (-not $ui.ResCats.SelectedItem) { $overview = $false; $catSel = ''; $ui.ResCats.SelectedItem = @($ui.ResCats.Items | Where-Object { "$($_.Tag)" -eq '' })[0] }
    }
    finally { $script:ResBusy = $false }
    $catFilter = if ($overview) { '' } else { $catSel }
    $shown = New-Object System.Collections.Generic.List[object]
    foreach ($f in $bySev) { if (-not $catFilter -or $f.Category -eq $catFilter) { $shown.Add($f) } }
    $ui.ResGrid.Columns[4].Visibility = if ($catFilter) { 'Collapsed' } else { 'Visible' }
    # The overview takes the place of the table and the details.
    $ui.ResOverviewBox.Visibility = if ($overview) { 'Visible' } else { 'Collapsed' }
    foreach ($el in $ui.ResGrid, $ui.ResDetailBox, $ui.ResSplit) { $el.Visibility = if ($overview) { 'Collapsed' } else { 'Visible' } }
    Update-ScoreBadge $hostSel
    if ($overview) { Show-ResultsOverview $hostSel }

    # The table: a new list loses the sort of the columns, so it is put back.
    $was = $ui.ResGrid.SelectedItem
    $sorts = @($ui.ResGrid.Items.SortDescriptions)
    $ui.ResGrid.ItemsSource = $shown.ToArray()
    foreach ($sd in $sorts) { $ui.ResGrid.Items.SortDescriptions.Add($sd) }
    foreach ($col in $ui.ResGrid.Columns) {
        $sd = @($sorts | Where-Object { $_.PropertyName -eq $col.SortMemberPath })
        $col.SortDirection = if ($sd.Count) { $sd[0].Direction } else { $null }
    }
    $keep = if ($was) { @($shown | Where-Object { $_.Type -eq $was.Type -and $_.Host -eq $was.Host -and $_.Object -eq $was.Object })[0] } else { $null }
    $ui.ResGrid.SelectedItem = if ($keep) { $keep } elseif ($ui.ResGrid.Items.Count) { $ui.ResGrid.Items[0] } else { $null }
    if ($ui.ResGrid.SelectedItem) { $ui.ResGrid.ScrollIntoView($ui.ResGrid.SelectedItem) }
    else { Show-ResultDetail $null }

    $ui.ResEmpty.Text = if (-not $script:Res -or -not $script:Res.Stamp) { 'The findings of the last report appear here, by category.' }
    elseif ($rows.Count -eq 0) { 'No findings in this report.' }
    elseif ($shown.Count -eq 0) { 'No finding matches these filters.' }
    else { '' }
    $ui.ResEmpty.Visibility = if ($ui.ResEmpty.Text -and -not $overview) { 'Visible' } else { 'Collapsed' }
}

function Get-SummaryHosts {
    # The hosts of the report's overview (an earlier report has none).
    if (-not $script:Res -or -not $script:Res.Summary) { return }
    @($script:Res.Summary.hosts) | Where-Object { $_ -and $_.name }
}
function Get-ScoreFor {
    # The score of the host chosen, or of the only host; with several, the lowest (and its host).
    param([string]$HostSel)
    $all = @(Get-SummaryHosts | Where-Object { $null -ne $_.score })
    if ($HostSel) { $all = @($all | Where-Object { $_.name -eq $HostSel }) }
    if ($all.Count -eq 0) { return }
    $low = @($all | Sort-Object { [int]$_.score })[0]
    return [pscustomobject]@{ Score = [int]$low.score; Grade = "$($low.grade)"; Host = "$($low.name)"; Count = $all.Count }
}
function Get-GradeColors {
    param([string]$Grade)
    if ($Grade -in 'A', 'B') { return @('#84CC5F', '#161513') }
    if ($Grade -in 'C', 'D') { return @('#F2B632', '#161513') }
    return @('#E2372A', '#FFFDF8')
}
function Update-ScoreBadge {
    param([string]$HostSel)
    $s = Get-ScoreFor $HostSel
    if (-not $s) { $ui.ScoreBadge.Visibility = 'Collapsed'; return }
    $c = Get-GradeColors $s.Grade
    $ui.ScoreBadge.Background = New-Brush $c[0]
    $ui.ScoreNum.Foreground = New-Brush $c[1]; $ui.ScoreLbl.Foreground = New-Brush $c[1]
    $ui.ScoreNum.Text = "$($s.Score)"
    $ui.ScoreLbl.Text = if ($s.Count -gt 1) { "lowest score, grade $($s.Grade)" } else { "score, grade $($s.Grade)" }
    $ui.ScoreBadge.ToolTip = if ($s.Count -gt 1) { "The lowest of $($s.Count) hosts: $($s.Host). Choose a host to see its own." } else { 'Exposure score out of 100 (the DISA STIG rules are compliance and stay out of it).' }
    $ui.ScoreBadge.Visibility = 'Visible'
}

function Add-OvText {
    # A paragraph of the overview.
    param([string]$Text, [switch]$Heading, [switch]$Muted, [string]$Color = '')
    $t = New-Object System.Windows.Controls.TextBlock
    $t.Text = $Text; $t.TextWrapping = 'Wrap'; $t.Margin = '0,0,0,6'
    if ($Heading) { $t.FontFamily = 'Bahnschrift, Segoe UI'; $t.FontSize = 19; $t.FontWeight = 'Bold'; $t.Margin = '0,16,0,6' }
    if ($Muted) { $t.Foreground = New-Brush '#5F5A51' }
    if ($Color) { $t.Foreground = New-Brush $Color; $t.FontWeight = 'SemiBold' }
    [void]$ui.ResOverview.Children.Add($t)
}
function New-OvPill {
    # A coloured label (score, severity, maturity) for a cell of the overview.
    param([string]$Text, [string]$Back, [string]$Fore = '#161513')
    $b = New-Object System.Windows.Controls.Border
    $b.Background = New-Brush $Back; $b.BorderBrush = New-Brush '#161513'; $b.BorderThickness = '2'; $b.Padding = '6,0'; $b.HorizontalAlignment = 'Left'
    $t = New-Object System.Windows.Controls.TextBlock; $t.Text = $Text; $t.FontWeight = 'Bold'; $t.Foreground = New-Brush $Fore
    $b.Child = $t
    return $b
}
function Add-OvTable {
    # A table of the overview: a header row, then the rows (a cell is text or an element).
    param([string[]]$Headers, $Rows)
    # One row comes back from a foreach as the row itself, not as a list of one row.
    if ($null -eq $Rows) { $Rows = @() }
    elseif (@($Rows).Count -gt 0 -and @($Rows)[0] -isnot [System.Array]) { $Rows = @(, $Rows) }
    $g = New-Object System.Windows.Controls.Grid
    $g.Margin = '0,2,0,8'; $g.HorizontalAlignment = 'Left'
    foreach ($i in 0..($Headers.Count - 1)) { $g.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::Auto })) }
    $r = 0
    foreach ($row in @(, $Headers) + @($Rows)) {
        $g.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
        for ($c = 0; $c -lt $Headers.Count; $c++) {
            $cell = New-Object System.Windows.Controls.Border
            $cell.Padding = '8,4'
            $cell.Background = New-Brush $(if ($r -eq 0) { '#161513' } elseif ($r % 2) { '#FFFDF8' } else { '#F3EFE6' })
            $v = if ($c -lt @($row).Count) { @($row)[$c] } else { '' }
            if ($v -is [System.Windows.UIElement]) { $cell.Child = $v }
            else {
                $t = New-Object System.Windows.Controls.TextBlock
                $t.Text = "$v"; $t.TextWrapping = 'Wrap'; $t.MaxWidth = 440; $t.VerticalAlignment = 'Center'
                if ($r -eq 0) { $t.Foreground = New-Brush '#F3EFE6'; $t.FontWeight = 'Bold' }
                $cell.Child = $t
            }
            [System.Windows.Controls.Grid]::SetRow($cell, $r); [System.Windows.Controls.Grid]::SetColumn($cell, $c)
            [void]$g.Children.Add($cell)
        }
        $r++
    }
    [void]$ui.ResOverview.Children.Add($g)
}
function New-HostLink {
    # A host name that chooses that host in the filters.
    param([string]$Name)
    $tb = New-Object System.Windows.Controls.TextBlock
    $link = New-Object System.Windows.Documents.Hyperlink (New-Object System.Windows.Documents.Run $Name)
    $link.Tag = $Name; $link.Foreground = New-Brush '#8A5A00'; $link.FontWeight = 'SemiBold'
    $link.Add_Click({ param($s) $ui.ResHost.SelectedItem = @($ui.ResHost.Items | Where-Object { "$($_.Tag)" -eq "$($s.Tag)" })[0] })
    $tb.Inlines.Add($link)
    return $tb
}

function Show-ResultsOverview {
    # What the HTML report says besides the findings, for the host chosen or for all of them.
    param([string]$HostSel)
    $ui.ResOverview.Children.Clear()
    $sum = if ($script:Res) { $script:Res.Summary } else { $null }
    if (-not $sum) {
        Add-OvText 'No overview in this report' -Heading
        Add-OvText 'It was written by an earlier HostBadger, which did not keep the scores and the other figures for the window. Analyze again, or open the HTML report. The categories on the left list its findings.' -Muted
        return
    }
    $all = @(Get-SummaryHosts)
    # @() around the if: one host would come back as the object, which has no Count on 5.1.
    $hs = @(if ($HostSel) { $all | Where-Object { $_.name -eq $HostSel } } else { $all })
    $mineOnly = { param($x) -not $HostSel -or "$($x.host)" -eq $HostSel }

    Add-OvText $(if ($HostSel) { $HostSel } else { "Hosts ($($all.Count))" }) -Heading
    # The change since the host's previous run, when the score history has one (reports of 2.1 and later).
    $withChange = @($all | Where-Object { $_.PSObject.Properties['scoreChange'] -and $null -ne $_.scoreChange }).Count -gt 0
    $rows = foreach ($x in @($hs | Sort-Object { [int]$_.score })) {
        $c = Get-GradeColors "$($x.grade)"
        $cells = New-Object System.Collections.Generic.List[object]
        $cells.Add($(if ($all.Count -gt 1 -and -not $HostSel) { New-HostLink "$($x.name)" } else { "$($x.name)" })); $cells.Add("$($x.role)"); $cells.Add((New-OvPill "$($x.score)  $($x.grade)" $c[0] $c[1]))
        if ($withChange) { $cells.Add($(if ($x.PSObject.Properties['scoreChange'] -and $null -ne $x.scoreChange) { "$(if ([int]$x.scoreChange -gt 0) { '+' })$($x.scoreChange) since $("$($x.scorePreviousCollected)".Substring(0, [Math]::Min(10, "$($x.scorePreviousCollected)".Length)))" } else { 'first run' })) }
        foreach ($v in "$($x.findings)", "$($x.severity.Critical)", "$($x.severity.High)", "$($x.severity.Medium)", "$($x.severity.Low)", "$(@($x.notEvaluated).Count)", "$($x.collected)", "$($x.collectedAs)") { $cells.Add($v) }
        , $cells.ToArray()
    }
    $heads = @('Host', 'Role', 'Score') + @(if ($withChange) { 'Change' }) + @('Findings', 'Critical', 'High', 'Medium', 'Low', 'Not evaluated', 'Collected', 'Collected as')
    Add-OvTable -Headers $heads -Rows @($rows)
    Add-OvText 'The score counts each check that fired once, at its worst severity (Critical 20, High 8, Medium 3, Low 1, the Low ones 10 at most), and is capped at 35 with a Critical and 65 with a High. The DISA STIG rules are compliance and stay out of it.' -Muted

    if ($hs.Count -eq 1) {
        $x = $hs[0]
        $edr = @($x.edr | Where-Object { $_ -and $_.name })
        Add-OvTable -Headers @('This host', '') -Rows @(
            , @('Operating system', "$($x.os)")
            , @('Collected', "$($x.collected), as $($x.collectedAs)")
            , @('EDR', $(if ($edr.Count) { ($edr | ForEach-Object { "$($_.name) ($($_.state))" }) -join ', ' } elseif ($x.edrKnown) { 'none found' } else { 'not known (services not read)' }))
            , @('Programs installed', "$($x.softwareCount)")
            , @('Missing updates', $(if ($x.updatesSource) { "searched with $($x.updatesSource)" } else { 'not searched (Search missing updates when collecting)' }))
            , @('DISA STIG rules judged', "$($x.stigEvaluated)"))
        $trend = @(if ($x.PSObject.Properties['trend']) { $x.trend | Where-Object { $_ } })
        if ($trend.Count -gt 1) { Add-OvText "Score over the last runs: $((@($trend | Select-Object -Last 10) | ForEach-Object { "$($_.score) ($("$($_.collected)".Substring(0, 10)))" }) -join ', ')." -Muted }
        if ("$($x.collectedAs)" -eq 'standard user') { Add-OvText 'Collected as a standard user: some checks could not be read. Collect as administrator or SYSTEM for full coverage.' -Color '#B3261E' }
        $ne = @($x.notEvaluated | Where-Object { $_ -and $_.title })
        if ($ne.Count) {
            Add-OvText "Not evaluated ($($ne.Count))" -Heading
            Add-OvText 'These checks were not judged on this host: they are neither clean nor findings.' -Muted
            Add-OvTable -Headers @('Check', 'Why') -Rows @($ne | ForEach-Object { , @("$($_.title)", "$($_.reason)") })
        }
    }

    Add-OvText 'Frameworks' -Heading
    $cmp = $sum.compliance
    if ($cmp -and [int]$cmp.cisApplicable -gt 0) { Add-OvText "CIS-based checks: $([int]$cmp.cisApplicable - [int]$cmp.cisFailed) of $($cmp.cisApplicable) passed on the hosts of the report ($($cmp.cisFailed) fired). A check can cover several benchmark rules." }
    if ($cmp -and [int]$cmp.stigEvaluated -gt 0) { Add-OvText "DISA STIG: $([int]$cmp.stigEvaluated - [int]$cmp.stigFailed) of $($cmp.stigEvaluated) registry rules judged passed ($($cmp.stigFailed) failed)." }
    # By product, for the hosts shown (reports before 2.0 have no per-product figures).
    $byStig = [ordered]@{}
    foreach ($x in $hs) {
        foreach ($s in @($x.stig | Where-Object { $_ -and $_.product })) {
            if (-not $byStig.Contains("$($s.product)")) { $byStig["$($s.product)"] = @(0, 0) }
            $byStig["$($s.product)"] = @(($byStig["$($s.product)"][0] + [int]$s.evaluated), ($byStig["$($s.product)"][1] + [int]$s.failed))
        }
    }
    if ($byStig.Count) {
        $rows = foreach ($k in $byStig.Keys) {
            $ev = $byStig[$k][0]; $ok = $ev - $byStig[$k][1]; $pct = [int][Math]::Round(100 * $ok / [Math]::Max(1, $ev))
            , @($k, (New-OvPill "$pct%" $(if ($pct -ge 80) { '#84CC5F' } elseif ($pct -ge 50) { '#F2B632' } else { '#FBD9D2' }) '#161513'), "$ok of $ev")
        }
        Add-OvText "DISA STIG by product$(if (-not $HostSel -and $all.Count -gt 1) { ' (all hosts together)' })" -Color '#161513'
        Add-OvTable -Headers @('Product', 'Compliant', 'Rules met') -Rows @($rows)
    }
    $e8Hosts = @($hs | Where-Object { @($_.e8 | Where-Object { $_ -and $_.strategy }).Count })
    if ($e8Hosts.Count -eq 1) {
        $rows = foreach ($s in @($e8Hosts[0].e8 | Where-Object { $_ -and $_.strategy })) {
            $txt = if ($s.note) { 'not visible' } elseif ($s.notApplicable) { 'n/a' } else { "ML$($s.level)" }
            $back = if ($s.note -or $s.notApplicable) { '#E8E2D4' } elseif ([int]$s.level -ge 2) { '#84CC5F' } elseif ([int]$s.level -eq 1) { '#F2B632' } else { '#FBD9D2' }
            , @("$($s.strategy)", (New-OvPill $txt $back), $(if ($s.note) { "$($s.note)" } elseif ($s.capped) { 'a requirement of the next level could not be judged' } else { '' }))
        }
        Add-OvText 'Essential Eight maturity (from what a host shows)' -Color '#161513'
        Add-OvTable -Headers @('Strategy', 'Level', 'Note') -Rows @($rows)
    }
    elseif ($e8Hosts.Count -gt 1) {
        $by = [ordered]@{}
        foreach ($x in $e8Hosts) { foreach ($s in @($x.e8 | Where-Object { $_ -and $_.strategy -and -not $_.note -and -not $_.notApplicable })) { if (-not $by.Contains("$($s.strategy)")) { $by["$($s.strategy)"] = New-Object System.Collections.Generic.List[int] }; $by["$($s.strategy)"].Add([int]$s.level) } }
        $rows = foreach ($k in $by.Keys) { $l = $by[$k]; $min = ($l | Measure-Object -Minimum).Minimum; , @($k, "ML$min", "$(@($l | Where-Object { $_ -eq $min }).Count) of $($l.Count)") }
        Add-OvText 'Essential Eight maturity: the lowest level among the hosts (choose a host for its own)' -Color '#161513'
        Add-OvTable -Headers @('Strategy', 'Lowest', 'Hosts at it') -Rows @($rows)
    }
    $acnHosts = @($hs | Where-Object { $_.acn })
    if ($acnHosts.Count) {
        Add-OvText 'NIS2, ACN basic measures (requirements a host can show)' -Color '#161513'
        Add-OvTable -Headers @('Host', 'Met', 'Not met', 'Not judged') -Rows @($acnHosts | ForEach-Object { , @("$($_.name)", "$($_.acn.met)", "$($_.acn.unmet)", "$($_.acn.unknown)") })
    }
    if ([int]$sum.hidden.cis -gt 0 -or [int]$sum.hidden.stig -gt 0) { Add-OvText "The HTML report hides $([int]$sum.hidden.cis) CIS-based and $([int]$sum.hidden.stig) DISA STIG finding(s); the CIS-based and DISA STIG boxes above show them here." -Muted }

    $cmpRun = $sum.comparison
    if ($cmpRun) {
        $res = @($cmpRun.resolved | Where-Object { $_ -and (& $mineOnly $_) })
        Add-OvText "Compared with $($cmpRun.previous)" -Heading
        Add-OvText "$($cmpRun.new) new, $($cmpRun.persisting) still there, $(@($cmpRun.resolved | Where-Object { $_ }).Count) resolved (on the whole report)."
        if ($res.Count) { Add-OvTable -Headers @('Resolved', 'Finding', 'Host', 'Object') -Rows @($res | ForEach-Object { , @((New-OvPill "$($_.severity)" $(if ($script:SevColors.ContainsKey("$($_.severity)")) { $script:SevColors["$($_.severity)"] } else { '#E8E2D4' }) $(if ("$($_.severity)" -eq 'Critical') { '#FFFDF8' } else { '#161513' })), "$($_.title)", "$($_.host)", "$($_.object)") }) }
    }

    $acc = @($sum.exceptions.accepted | Where-Object { $_ -and $_.type -and (& $mineOnly $_) })
    $exp = @($sum.exceptions.expired | Where-Object { $_ -and $_.type })
    if ($acc.Count -or $exp.Count) {
        Add-OvText "Accepted risks ($($acc.Count))" -Heading
        Add-OvText 'Findings covered by the exceptions file: they are not in the categories.' -Muted
        if ($acc.Count) { Add-OvTable -Headers @('Finding', 'Host', 'Object', 'Reason', 'Owner', 'Expires') -Rows @($acc | ForEach-Object { , @("$($_.title)", "$($_.host)", "$($_.object)", "$($_.reason)", "$($_.owner)", "$(if ($_.expires) { $_.expires } else { 'never' })") }) }
        if ($exp.Count) { Add-OvText "Expired, ignored (their findings are back): $(($exp | ForEach-Object { "$($_.type) / $($_.host) / $($_.object) ($($_.expires))" }) -join '; ')" -Color '#B3261E' }
    }

    $rem = @($sum.remediation | Where-Object { $_ -and $_.host -and (& $mineOnly $_) })
    if ($rem.Count) {
        Add-OvText 'Fix scripts' -Heading
        Add-OvText "Written next to the report ($((Split-Path -Leaf (($script:Res.Path -replace '(?i)\.html?$', '') + '_fixes'))) folder). Each previews by default; -Apply as administrator on that host changes it and writes a rollback file." -Muted
        Add-OvTable -Headers @('Host', 'Script', 'Changes', 'Findings fixed', 'Findings without a fix') -Rows @($rem | ForEach-Object { , @("$($_.host)", $(if ($_.file) { "$($_.file)" } else { 'none (nothing to change)' }), "$($_.actions)", "$($_.fixable)", "$($_.notFixable)") })
    }

    if ($sum.ai) {
        Add-OvText "AI summary ($($sum.ai.model))" -Heading
        if ($sum.ai.summary) { Add-OvText "$($sum.ai.summary)" }
        $qw = @($sum.ai.quickWins | Where-Object { $_ })
        if ($qw.Count) { Add-OvText 'Quick wins' -Color '#161513'; foreach ($q in $qw) { Add-OvText "-  $q" } }
        $plan = @($sum.ai.plan | Where-Object { $_ -and $_.title })
        if ($plan.Count) { Add-OvTable -Headers @('Plan', 'Effort', 'Why') -Rows @($plan | ForEach-Object { , @("$($_.title)", "$($_.effort)", "$($_.rationale)") }) }
        Add-OvText 'Written by a language model from pseudonymized findings: check it against the findings.' -Muted
    }
}

function Add-ResultField {
    # One labelled field of the details: selectable text, so it can be copied.
    param([string]$Label, [string]$Text, [switch]$Mono)
    if (-not "$Text".Trim()) { return }
    $l = New-Object System.Windows.Controls.TextBlock
    $l.Text = $Label.ToUpperInvariant(); $l.FontSize = 11; $l.FontWeight = 'Bold'; $l.Foreground = New-Brush '#5F5A51'; $l.Margin = '0,6,0,2'
    $t = New-Object System.Windows.Controls.TextBox
    $t.Style = $window.FindResource('ReadOnlyText'); $t.Text = $Text
    if ($Mono) { $t.FontFamily = 'Cascadia Mono, Consolas'; $t.FontSize = 13 }
    [void]$ui.ResDetail.Children.Add($l); [void]$ui.ResDetail.Children.Add($t)
}

function Show-ResultDetail {
    # What was found, why it matters and how to fix it, for the finding chosen in the table.
    param($F)
    $d = $ui.ResDetail
    $d.Children.Clear()
    if (-not $F) {
        $t = New-Object System.Windows.Controls.TextBlock
        $t.Text = 'Choose a finding to see what was found, why it matters and how to fix it.'; $t.TextWrapping = 'Wrap'; $t.Foreground = New-Brush '#5F5A51'
        [void]$d.Children.Add($t)
        return
    }
    $info = (Get-CheckInfo)[$F.Type]
    $top = New-Object System.Windows.Controls.StackPanel; $top.Orientation = 'Horizontal'; $top.Margin = '0,0,0,8'
    $pill = New-Object System.Windows.Controls.Border
    $pill.Background = New-Brush $(if ($script:SevColors.ContainsKey($F.Severity)) { $script:SevColors[$F.Severity] } else { '#E8E2D4' })
    $pill.BorderBrush = New-Brush '#161513'; $pill.BorderThickness = '2'; $pill.Padding = '8,1'
    $pt = New-Object System.Windows.Controls.TextBlock; $pt.Text = $F.Severity; $pt.FontWeight = 'Bold'
    if ($F.Severity -eq 'Critical') { $pt.Foreground = New-Brush '#FFFDF8' }
    $pill.Child = $pt
    $cat = New-Object System.Windows.Controls.TextBlock; $cat.Text = $F.Category; $cat.Margin = '10,0,0,0'; $cat.VerticalAlignment = 'Center'; $cat.Foreground = New-Brush '#5F5A51'
    [void]$top.Children.Add($pill); [void]$top.Children.Add($cat)
    [void]$d.Children.Add($top)
    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text = $F.Title; $title.TextWrapping = 'Wrap'; $title.FontFamily = 'Bahnschrift, Segoe UI'; $title.FontSize = 19; $title.FontWeight = 'Bold'; $title.Margin = '0,0,0,6'
    [void]$d.Children.Add($title)
    Add-ResultField 'Host' $F.Host
    Add-ResultField 'Object' $F.Object -Mono
    Add-ResultField 'What was found' $F.Detail
    Add-ResultField 'Value on the host' $F.Found
    Add-ResultField 'Expected' $F.Expected
    if ($info) { Add-ResultField 'Why it matters' $info.Description }
    Add-ResultField 'How an attacker uses it' $F.Attacks
    if ($info) { Add-ResultField 'How to fix' $info.Remediation }
    if ($F.Cis) { Add-ResultField 'CIS rule' "$(if ($F.CisBenchmark) { "$($F.CisBenchmark), " })$($F.Cis)" }
    Add-ResultField 'MITRE ATT&CK' $F.Mitre
    Add-ResultField 'Check' $F.Type -Mono
    $fix = if ($script:Res -and $script:Res.Path) { Join-Path (($script:Res.Path -replace '(?i)\.html?$', '') + '_fixes') ('remediate_' + ($F.Host -replace '[^\w\-]', '_') + '.ps1') } else { '' }
    if ($fix -and (Test-Path -LiteralPath $fix)) { Add-ResultField 'Fix script of this host' "$fix`r`n(preview: run it; -Apply as administrator changes the host. The HTML report shows the fix line of each check.)" }
}

function Select-OtherReport {
    # An earlier report for the Results tab and the AI buttons (the analysis in memory belongs to the last run only).
    $d = New-Object Microsoft.Win32.OpenFileDialog; $d.Filter = 'HostBadger reports|*.html'
    $d.InitialDirectory = if ($script:LastReport) { Split-Path -Parent $script:LastReport } else { Get-ReportDir }
    if (-not $d.ShowDialog()) { return $false }
    if ($d.FileName -ne $script:LastReport) { $script:Kept = $false }
    $script:LastReport = $d.FileName
    $script:ReportChosen = $true
    Update-AiTarget; Update-Outputs
    Show-Results $script:LastReport
    return $true
}

# ---------------- Settings: the guided menu's global settings fill the form.
function Read-Settings {
    # Version 1 files had "kept" as the catalogs' default: their "kept" is read as "auto", as the menu does.
    if (-not (Test-Path -LiteralPath $script:SettingsPath)) { return $null }
    try { $s = [System.IO.File]::ReadAllText($script:SettingsPath) | ConvertFrom-Json } catch { return $null }
    if ([int]"0$($s.version)" -lt 2) {
        foreach ($cn in $script:GuiCatalogs.Keys) { if ($s.PSObject.Properties[$cn] -and "$($s.$cn)" -eq 'kept') { $s.$cn = 'auto' } }
        if ($s.PSObject.Properties['version']) { $s.version = 2 } else { $s | Add-Member -NotePropertyName version -NotePropertyValue 2 }
    }
    return $s
}
function Write-Settings {
    # Changes some keys of the settings file, keeping the others (the guided menu's included).
    param([hashtable]$Values)
    $s = [ordered]@{}
    $old = Read-Settings
    if ($old) { foreach ($p in $old.PSObject.Properties) { $s[$p.Name] = $p.Value } }
    $s['version'] = 2
    foreach ($k in $Values.Keys) { $s[$k] = $Values[$k] }
    $s['savedUtc'] = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC'
    $dir = Split-Path -Parent $script:SettingsPath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($script:SettingsPath, (ConvertTo-Json -InputObject $s), (New-Object System.Text.UTF8Encoding($false)))
}
function Test-AutoUpdateCheck { $s = Read-Settings; return [bool]($s -and $s.AutoUpdateCheck) }
function Get-SnapshotDir { $s = Read-Settings; if ($s -and $s.SnapshotDir) { return (Get-FullPath "$($s.SnapshotDir)") }; return (Join-Path $PWD.ProviderPath 'snapshots') }
function Get-ReportDir { $s = Read-Settings; if ($s -and $s.ReportDir) { return (Get-FullPath "$($s.ReportDir)") }; return (Join-Path $PWD.ProviderPath 'output') }
function Update-AiTarget {
    # Which report the AI buttons add their summary to: the last one, or one chosen from an earlier run.
    if (-not $script:LastReport -or -not (Test-Path -LiteralPath $script:LastReport)) { $ui.AiTargetText.Text = 'AI summary: no report yet. Analyze first, or choose an earlier report.'; return }
    $name = Split-Path -Leaf $script:LastReport
    if ($script:Kept) { $ui.AiTargetText.Text = "AI summary goes into $name (the analysis is in memory)."; return }
    $ui.AiTargetText.Text = "AI summary goes into $name (earlier report: its findings are read, nothing is analyzed or downloaded; its snapshot is needed for the tokens)."
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
    $ui.CollectNote.Text = "Read only: nothing on this machine changes. $(if ($script:IsAdmin) { 'Running as administrator: full coverage.' } else { 'Not administrator: some checks will be listed as not evaluated (Restart as admin for full coverage).' }) The snapshot describes this machine: keep it like any other sensitive file."
    # A TextBlock, so the long label wraps instead of running out of the card.
    $wu = New-Object System.Windows.Controls.TextBlock
    $wu.Text = "Search missing updates (the Windows Update service contacts $(Get-WuSource))"; $wu.TextWrapping = 'Wrap'
    $ui.UpdatesChk.Content = $wu
    $snapDir = Get-SnapshotDir
    $ui.CollectDirBox.Text = $snapDir
    Select-LatestSnapshot $snapDir
    if ($s -and "$($s.GuiSource)" -eq 'snapshots') { $ui.SrcSnap.IsChecked = $true } else { $ui.SrcMachine.IsChecked = $true }
    $repDir = Get-ReportDir
    $ui.ReportBox.Text = Join-Path $repDir "hostbadger_$(Get-Stamp).html"
    $last = Find-LatestReport $repDir
    if ($last) { $script:LastReport = $last.FullName }
    if ($s) {
        $ui.SkipAclChk.IsChecked = [bool]$s.SkipAcl; $ui.UpdatesChk.IsChecked = [bool]$s.CheckUpdates; $ui.PipesChk.IsChecked = [bool]$s.NamedPipes
        $ui.PerHostChk.IsChecked = [bool]$s.PerHost; $ui.StigChk.IsChecked = -not [bool]$s.SkipStig
        $ui.ShowCisChk.IsChecked = -not [bool]$s.HideCis; $ui.ShowStigChk.IsChecked = -not [bool]$s.HideStig
        $ui.AcnChk.IsChecked = [bool]$s.Nis2Acn; $ui.JsonlChk.IsChecked = [bool]$s.Jsonl; $ui.RemChk.IsChecked = [bool]$s.Remediation
        $ui.PrivacyChk.IsChecked = [bool]$s.RemediationPrivacy; $ui.DebloatChk.IsChecked = [bool]$s.RemediationDebloat
        $ui.AdminsBox.Text = "$($s.AllowedAdmins)"; $ui.EdrBox.Text = "$($s.ExpectedEdr)"; $ui.RatBox.Text = "$($s.AllowedRemoteTools)"; $ui.ExtBox.Text = "$($s.AllowedExtensions)"
        $ui.ExceptionsBox.Text = "$($s.ExceptionsFile)"; $ui.PolicyBox.Text = "$($s.PolicyFile)"
        if ($s.Encrypt -eq 'password') { $ui.EncPass.IsChecked = $true } elseif ($s.Encrypt -eq 'certificate') { $ui.EncCert.IsChecked = $true; $ui.EncCertBox.Text = "$($s.Certificate)" }
    }
    # Showing the STIG findings means nothing when they are not judged (as when the box is clicked).
    $ui.ShowStigChk.IsEnabled = [bool]$ui.StigChk.IsChecked
    # Fix script levels: one radio button each, with what it changes. The guided menu's "debloat and
    # telemetry only" is the level None with both boxes ticked.
    $prof = if ($s) { "$($s.RemediationProfile)" } else { '' }
    if ($prof -eq 'DebloatTelemetry') { $prof = 'None'; $ui.DebloatChk.IsChecked = $true; $ui.PrivacyChk.IsChecked = $true }
    elseif ($s -and $s.RemediationOnlyProfile) { $prof = 'None' }
    if (-not $script:Profiles.Contains($prof)) { $prof = '' }
    foreach ($k in $script:Profiles.Keys) {
        $p = $script:Profiles[$k]
        $rb = New-Object System.Windows.Controls.RadioButton
        $rb.GroupName = 'Profile'; $rb.Tag = $k; $rb.Style = $window.FindResource('OptionCard')
        $sp = New-Object System.Windows.Controls.StackPanel
        $t1 = New-Object System.Windows.Controls.TextBlock; $t1.Text = $p.Title; $t1.FontWeight = 'SemiBold'
        $t2 = New-Object System.Windows.Controls.TextBlock; $t2.Text = $p.Text; $t2.TextWrapping = 'Wrap'; $t2.Foreground = New-Brush '#5F5A51'; $t2.FontSize = 13
        [void]$sp.Children.Add($t1); [void]$sp.Children.Add($t2)
        $rb.Content = $sp
        $rb.IsChecked = ($k -eq $prof)
        # Click, not Checked: Strict turns the two options on, leaving it gives them back.
        $rb.Add_Click({ Update-RemPanel })
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
    Initialize-Results
    Update-AiInfo
    Update-AiTarget
    Update-Source
}
function Update-Source {
    # Only the part of the source that is chosen can be edited.
    $m = [bool]$ui.SrcMachine.IsChecked
    $ui.MachinePanel.IsEnabled = $m; $ui.MachinePanel.Opacity = if ($m) { 1 } else { 0.5 }
    $ui.SnapPanel.IsEnabled = -not $m; $ui.SnapPanel.Opacity = if ($m) { 0.5 } else { 1 }
    # The update search is part of the collection: nothing to search in snapshots already collected.
    $ui.UpdatesChk.IsEnabled = $m; $ui.UpdatesChk.Opacity = if ($m) { 1 } else { 0.5 }
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
        # What to select: the earlier choice, else the saved mode, else (auto, the default) the kept copy
        # when it is at most a week old and a download otherwise.
        $want = $was
        if (-not $want) {
            $mode = if ($s) { "$($s.$cn)" } else { '' }
            switch ($mode) {
                'online' { $want = 'online' }
                'off' { $want = $(if ($c.Shipped) { 'shipped' } else { 'none' }) }
                'kept' { $want = 'kept' }
                default { $want = $(if ($kept -and ((Get-Date) - $kept.LastWriteTime).TotalDays -le 7) { 'kept' } else { 'online' }) }
            }
        }
        if (-not $want -or ($want -eq 'kept' -and -not $kept)) { $want = $(if ($kept) { 'kept' } elseif ($c.Shipped) { 'shipped' } else { 'none' }) }
        $box.SelectedItem = @($box.Items | Where-Object { $_.Tag -eq $want })[0]
    }
}
function Get-CatalogChoice { param([string]$Name) $b = $script:CatalogBoxes[$Name]; if ($b.SelectedItem) { return "$($b.SelectedItem.Tag)" }; return '' }
function Get-ProfileChoice { $rb = @($ui.ProfilePanel.Children | Where-Object { $_.IsChecked })[0]; if ($rb) { return "$($rb.Tag)" }; return '' }
function Test-FixChoice {
    # A fix needs something to change: a level, or "No fix of the findings" with Debloat or telemetry.
    $rb = @($ui.ProfilePanel.Children | Where-Object { $_.IsChecked })
    if ($rb.Count -eq 0) { return $false }
    if ("$($rb[0].Tag)" -eq 'None') { return [bool]($ui.DebloatChk.IsChecked -or $ui.PrivacyChk.IsChecked) }
    return $true
}
function Update-Actions {
    # What can be pressed, from the form and from whether a step is running: one place for all of it.
    $busy = [bool]$script:Task
    $fixOk = Test-FixChoice
    $t = $ui.SnapshotBox.Text.Trim()
    $srcOk = [bool]$ui.SrcMachine.IsChecked -or ($t -and (Test-Path -LiteralPath $t))
    $ui.RunBtn.IsEnabled = (-not $busy) -and $srcOk
    $ui.RunBtn.ToolTip = if ($srcOk) { 'Changes nothing on any machine.' } else { 'Choose a snapshot file or folder that exists (File... or Folder...).' }
    $ui.FixBtn.IsEnabled = (-not $busy) -and $fixOk
    $ui.ApplyYesBtn.IsEnabled = (-not $busy) -and [bool]$script:ApplyPending; $ui.ApplyNoBtn.IsEnabled = $ui.ApplyYesBtn.IsEnabled
    $ui.StopBtn.IsEnabled = $busy -and -not $script:Stopping; $ui.FixStopBtn.IsEnabled = $ui.StopBtn.IsEnabled
    $ui.FixBtn.ToolTip = if ($fixOk) { 'Collect and analyze this machine, preview its fix script, then apply it after a warning (administrator).' } else { 'Choose what the fixes change first (above): a level, or "No fix of the findings" with Debloat or Disable telemetry.' }
    $ui.RemChk.IsEnabled = $fixOk
    $ui.RemOutText.Visibility = if ($fixOk -and $ui.RemChk.IsChecked) { 'Visible' } else { 'Collapsed' }
    $ui.RemChk.ToolTip = if ($fixOk) { 'Each time Analyze runs, remediate_<host>.ps1 is written next to the report, one per analyzed host, with the changes chosen in the Fix tab. Copy it to that host and run it there as administrator: it only shows what it would change until run with -Apply, and it writes a rollback file. Analyze itself never runs it.' } else { 'Nothing to write: in the Fix tab choose a level, or Debloat or Disable telemetry.' }
    # Sending needs the key; the dry run does not.
    $ui.AiSendBtn.IsEnabled = (-not $busy) -and [bool]$env:GEMINI_API_KEY
    $ui.AiSendBtn.ToolTip = if ($env:GEMINI_API_KEY) { $null } else { 'Set the Gemini API key in Settings first. AI: dry run writes the prompt without it.' }
}
function Update-RemPanel {
    # The choices stay editable; Strict includes debloat and telemetry.
    $p = Get-ProfileChoice
    $strict = $p -eq 'Strict'
    # Leaving Strict gives back the boxes as they were before it.
    if ($strict -and -not $script:BeforeStrict) { $script:BeforeStrict = @([bool]$ui.DebloatChk.IsChecked, [bool]$ui.PrivacyChk.IsChecked) }
    if (-not $strict -and $script:BeforeStrict) { $ui.DebloatChk.IsChecked = $script:BeforeStrict[0]; $ui.PrivacyChk.IsChecked = $script:BeforeStrict[1]; $script:BeforeStrict = $null }
    foreach ($c in $ui.DebloatChk, $ui.PrivacyChk) { $c.IsEnabled = -not $strict; if ($strict) { $c.IsChecked = $true } }
    # Analyze never changes anything (it writes the scripts when asked). Fix this machine, whatever the
    # source chosen above, collects and analyzes this machine, previews and applies after a warning.
    Update-Actions
    $ui.RemWarn.Text = "Fix this machine (button below) CHANGES THIS MACHINE, whatever the Analyze tab has under What to analyze: it collects and analyzes it (with the collection options of This machine there; a collection made in this window in the last $($script:FixReuseMinutes) minutes with the same options is used again; with No fix of the findings nothing is collected, the script holds the debloat and telemetry settings for the role of this machine), previews its fix script in the log and applies it only when you press Apply under the preview$(if ($script:IsAdmin) { '' } else { ' (needs administrator: Restart as admin first)' }), with a System Restore point first (Windows PowerShell 5.1) and a rollback file of every value changed. Changes marked NOT REVERSIBLE (removed apps, LSA protection) cannot be undone by it. Analyze changes nothing; for other hosts tick Also save a fix script for each host (Report, in the Analyze tab), analyze, and run each script on its host."
    $ui.RemWarn.Foreground = New-Brush '#3A1714'
    $rep = Get-FullPath $ui.ReportBox.Text.Trim()
    $ui.RemOutText.Text = "Written to $(($rep -replace '\.html?$', ''))_fixes: one remediate_<HOST>.ps1 per host. Preview: .\remediate_<HOST>.ps1   Apply, as administrator on that host: .\remediate_<HOST>.ps1 -Apply"}

function Get-AnalysisParams {
    # The form as the parameters of HostBadger.ps1 (the same ones the guided menu passes). ForFix: the fix
    # script of this machine is written whether or not the scripts are asked for with each analysis.
    param([switch]$ForFix)
    $ap = @{ Snapshot = $ui.SnapshotBox.Text.Trim(); OutHtml = (Get-FullPath $ui.ReportBox.Text.Trim()); NoLog = $true }
    # The other files are named after the report: without .html the JSON Lines file would be the report itself.
    if ($ap['OutHtml'] -and $ap['OutHtml'] -notmatch '(?i)\.html?$') { $ap['OutHtml'] += '.html' }
    # The analysis writes the per-host reports only with two hosts or more, so the box is always free.
    if ($ui.PerHostChk.IsChecked) { $ap['PerHost'] = $true }
    if (-not $ui.StigChk.IsChecked) { $ap['SkipStig'] = $true } elseif (-not $ui.ShowStigChk.IsChecked) { $ap['HideStig'] = $true }
    if (-not $ui.ShowCisChk.IsChecked) { $ap['HideCis'] = $true }
    if ($ui.AcnChk.IsChecked) { $ap['Nis2Acn'] = $true }
    if ($ui.JsonlChk.IsChecked) { $ap['OutJsonl'] = $ap['OutHtml'] -replace '\.html?$', '.jsonl' }
    # The score of every run, next to the reports: each report shows how the scores moved.
    if ($ap['OutHtml'] -and (Split-Path -Parent $ap['OutHtml'])) { $ap['History'] = Join-Path (Split-Path -Parent $ap['OutHtml']) 'hostbadger-history.csv' }
    if (($ui.RemChk.IsChecked -and (Test-FixChoice)) -or $ForFix) {
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
        $v = $pair[1].Text.Trim(); if ($v) { $ap[$pair[0]] = Get-FullPath $v }
    }
    if ($ui.SnapPassBox.SecurePassword.Length -gt 0) { $ap['SnapshotPassword'] = $ui.SnapPassBox.SecurePassword.Copy() }
    # The analysis stays in the background runspace's memory for the AI buttons (never on disk).
    $ap['AiLater'] = $true
    return $ap
}

function Get-ParamsSignature {
    # What decides the findings and the fix script of an analysis (not where its files go): two analyses
    # with the same signature on the same snapshot write the same fix script.
    param($Ap)
    $skip = 'Snapshot', 'OutHtml', 'OutJsonl', 'OutRemediation', 'History', 'AiLater', 'SnapshotPassword', 'NoLog', 'PerHost'
    (@($Ap.Keys | Where-Object { $skip -notcontains $_ } | Sort-Object) | ForEach-Object { "$_=$(@($Ap[$_]) -join ',')" }) -join ';'
}

function Get-CollectOptions {
    "SkipAcl=$([bool]$ui.SkipAclChk.IsChecked);CheckUpdates=$([bool]$ui.UpdatesChk.IsChecked);NamedPipes=$([bool]$ui.PipesChk.IsChecked)"
}

function Save-FormChoices {
    # Each run keeps the choices of the form for the next one (folders and keys are in Settings).
    # The guided menu knows the levels and DebloatTelemetry (no finding fixes, debloat and telemetry).
    $lvl = Get-ProfileChoice
    $prof = if ($lvl -ne 'None') { $lvl } elseif ($ui.DebloatChk.IsChecked -and $ui.PrivacyChk.IsChecked) { 'DebloatTelemetry' } else { '' }
    $v = @{
        SkipAcl = [bool]$ui.SkipAclChk.IsChecked; CheckUpdates = [bool]$ui.UpdatesChk.IsChecked; NamedPipes = [bool]$ui.PipesChk.IsChecked
        PerHost = [bool]$ui.PerHostChk.IsChecked; SkipStig = -not [bool]$ui.StigChk.IsChecked; HideCis = -not [bool]$ui.ShowCisChk.IsChecked; HideStig = -not [bool]$ui.ShowStigChk.IsChecked
        Nis2Acn = [bool]$ui.AcnChk.IsChecked; Jsonl = [bool]$ui.JsonlChk.IsChecked; Remediation = [bool]$ui.RemChk.IsChecked
        RemediationProfile = $prof; RemediationOnlyProfile = ($lvl -eq 'None'); RemediationDebloat = [bool]$ui.DebloatChk.IsChecked; RemediationPrivacy = [bool]$ui.PrivacyChk.IsChecked
        GuiSource = $(if ($ui.SrcSnap.IsChecked) { 'snapshots' } else { 'machine' })
        AllowedAdmins = $ui.AdminsBox.Text.Trim(); ExpectedEdr = $ui.EdrBox.Text.Trim(); AllowedRemoteTools = $ui.RatBox.Text.Trim(); AllowedExtensions = $ui.ExtBox.Text.Trim()
        ExceptionsFile = $ui.ExceptionsBox.Text.Trim(); PolicyFile = $ui.PolicyBox.Text.Trim()
    }
    # A catalog keeps its saved mode unless the form now asks for something else (a download, or none).
    # A kept copy picked in the form stays "auto" (the default) unless the saved mode is "kept".
    $old = Read-Settings
    foreach ($cn in $script:GuiCatalogs.Keys) {
        $oldMode = if ($old -and "$($old.$cn)") { "$($old.$cn)" } else { 'auto' }
        $m = switch (Get-CatalogChoice $cn) { 'online' { 'online' } 'none' { 'off' } 'shipped' { 'off' } default { 'kept' } }
        if ($m -ne 'off' -and ($oldMode -eq 'auto' -or ($m -eq 'kept' -and $oldMode -ne 'kept'))) { $m = 'auto' }
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
    $su.SetAiOffer.IsChecked = -not ($s -and "$($s.Ai)" -eq 'N')
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
            $ci.Content = if ($m -eq 'off') { "Never download: $(if ($c.Shipped) { 'the shipped copy' } else { 'not used' })" } elseif ($m -eq 'kept') { "Newest kept copy whatever its age, else $(if ($c.Shipped) { 'the shipped copy' } else { 'not used' })" } else { $script:CatalogModes[$m] }
            [void]$box.Items.Add($ci)
        }
        $cur = if ($s -and "$($s.$cn)" -in $script:CatalogModes.Keys) { "$($s.$cn)" } else { 'auto' }
        $box.SelectedItem = @($box.Items | Where-Object { $_.Tag -eq $cur })[0]
        [System.Windows.Controls.Grid]::SetRow($box, $row); [System.Windows.Controls.Grid]::SetColumn($box, 1)
        [void]$su.SetCatalogGrid.Children.Add($lbl); [void]$su.SetCatalogGrid.Children.Add($box)
        $sw.Boxes[$cn] = $box
        $row++
    }
    if ($s -and $s.Encrypt -eq 'password') { $su.SetEncPass.IsChecked = $true } elseif ($s -and $s.Encrypt -eq 'certificate') { $su.SetEncCert.IsChecked = $true } elseif ($s -and $s.Encrypt -eq 'none') { $su.SetEncNone.IsChecked = $true }
    $su.SetCert.Text = if ($s) { "$($s.Certificate)" } else { '' }
    $su.SetAutoUpdate.IsChecked = Test-AutoUpdateCheck
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
        Ai = $(if (-not $su.SetAiOffer.IsChecked) { 'N' } else { $oldAi = "$((Read-Settings).Ai)"; if ($oldAi -and $oldAi -ne 'N') { $oldAi } else { 'A' } })
        Encrypt = $enc; Certificate = $su.SetCert.Text.Trim(); AutoUpdateCheck = [bool]$su.SetAutoUpdate.IsChecked
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
    $ap = Get-AnalysisParams -ForFix:$script:ForFix
    if (-not $ap['Snapshot'] -or -not (Test-Path -LiteralPath $ap['Snapshot'])) { [void][System.Windows.MessageBox]::Show('Choose a snapshot file, zip or folder first.', 'HostBadger'); return }
    $hbx = @(Get-PasswordSnapshots $ap['Snapshot'])
    if ($hbx.Count -gt 0 -and -not $ap['SnapshotPassword']) { [void][System.Windows.MessageBox]::Show("$($hbx.Count) snapshot(s) encrypted with a password: type it first.", 'HostBadger'); return }
    $dir = Split-Path -Parent $ap['OutHtml']
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $script:Kept = $false
    $script:ReportChosen = $false
    $script:Pending = $ap['OutHtml']
    # An analysis of this machine's last collection that writes the fix scripts can serve the next Fix.
    $script:PendingBasis = $null
    if ($ap['OutRemediation'] -and $script:LastSnapshot -and $ap['Snapshot'] -eq $script:LastSnapshot) {
        $script:PendingBasis = @{ Snapshot = $ap['Snapshot']; Signature = (Get-ParamsSignature $ap); Fixes = $ap['OutRemediation'] }
    }
    Start-GuiTask -Label 'Analyzing' -Work $script:RunScript -Arguments @((Join-Path $root 'HostBadger.ps1'), $ap) -Done {
        param($t)
        $ok = Test-Path -LiteralPath $script:Pending
        $script:Kept = $ok
        Set-Busy $false $(if ($ok) { 'Report ready' } else { 'The analysis did not finish' })
        if ($ok -and $script:PendingBasis) { $script:FixBasis = $script:PendingBasis }
        if ($ok) {
            $script:LastReport = $script:Pending
            Write-GuiLog -Path ($script:LastReport -replace '\.html?$', '.log') -Lines $t.Lines
            $ui.ReportBox.Text = Join-Path (Split-Path -Parent $script:LastReport) "hostbadger_$(Get-Stamp).html"
            Update-CatalogChoices
            Update-RemPanel
        }
        Update-Outputs
        if ($ok) { Show-Results $script:LastReport }
        # The fix preview prints in the log, so the window stays on it; otherwise the findings are shown.
        if ($ok -and $script:ApplyAfter) { $script:ApplyAfter = $false; Invoke-FixPreview }
        elseif ($ok) { $ui.Tabs.SelectedItem = $ui.TabResults; Invoke-AiOffer }
    }
}
function Write-GuiLog {
    # The run log next to the report (the window shows the same lines).
    param([string]$Path, $Lines)
    try { [System.IO.File]::WriteAllText($Path, (($Lines -join [Environment]::NewLine) + [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false))); Add-Log "Run log: $Path" } catch { }
}

function New-ChoiceWindow {
    # A question with named buttons (a MessageBox only has Yes and No). Buttons: Tag, Label and, for one
    # that cannot be pressed now, Off (the reason, shown as its tooltip); the first one that can is the primary.
    param([string]$Heading, [string]$Text, [object[]]$Buttons)
    $d = New-XamlWindow ([xml]($windowOpen + @"
        Title="HostBadger" Width="600" SizeToContent="Height" ResizeMode="NoResize"
        Background="#F3EFE6" FontFamily="Segoe UI" FontSize="14" Foreground="#161513" WindowStartupLocation="CenterOwner">
$resources
  <StackPanel Margin="22">
    <TextBlock x:Name="ChoiceHead" Style="{StaticResource H2}"/>
    <TextBlock x:Name="ChoiceText" TextWrapping="Wrap" Margin="0,0,0,18"/>
    <StackPanel x:Name="ChoiceButtons" Orientation="Horizontal" HorizontalAlignment="Right"/>
  </StackPanel>
</Window>
"@))
    $d.Ui.ChoiceHead.Text = $Heading
    $d.Ui.ChoiceText.Text = $Text
    $primary = $false
    foreach ($b in $Buttons) {
        $btn = New-Object System.Windows.Controls.Button
        $btn.Content = $b.Label; $btn.Tag = $b.Tag; $btn.Margin = '10,0,0,0'
        if ($b.Off) { $btn.IsEnabled = $false; $btn.ToolTip = $b.Off; [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($btn, $true) }
        elseif (-not $primary) { $btn.Style = $d.Window.FindResource('Primary'); $primary = $true }
        $btn.Add_Click({ param($s) $script:ChoiceResult = "$($s.Tag)"; [System.Windows.Window]::GetWindow($s).Close() })
        [void]$d.Ui.ChoiceButtons.Children.Add($btn)
    }
    return $d
}
function Show-Choice {
    # The Tag of the button pressed; '' when the window is closed.
    param([string]$Heading, [string]$Text, [object[]]$Buttons)
    $d = New-ChoiceWindow -Heading $Heading -Text $Text -Buttons $Buttons
    $script:ChoiceResult = ''
    $d.Window.Owner = $window
    [void]$d.Window.ShowDialog()
    return $script:ChoiceResult
}
function Get-AiOfferButtons {
    @(
        @{ Tag = 'send'; Label = 'Send to Gemini'; Off = $(if (-not $env:GEMINI_API_KEY) { 'Set the Gemini API key in Settings first.' }) }
        @{ Tag = 'dry'; Label = 'Dry run (write the prompt only)' }
        @{ Tag = ''; Label = 'Not now' }
    )
}
function Invoke-AiOffer {
    # After an analysis, on the analysis in memory: not with no findings (nothing to summarize), and not
    # when the settings turn the question off.
    $s = Read-Settings
    if (($s -and "$($s.Ai)" -eq 'N') -or -not $script:Kept -or -not $script:Res -or @($script:Res.Rows).Count -eq 0) { return }
    $text = "$(@($script:Res.Rows).Count) finding(s) in $(Split-Path -Leaf $script:LastReport). The AI summary uses this analysis: nothing is analyzed or downloaded again.`n`nThe dry run writes the prompt and sends nothing, so you can read it first."
    switch (Show-Choice -Heading 'Add an AI summary?' -Text $text -Buttons (Get-AiOfferButtons)) {
        'send' { Invoke-Ai $true }
        'dry' { Invoke-Ai $false }
    }
}
function Select-AiReport {
    # No analysis in memory: which report the AI step works on. $true when one is chosen.
    if ($script:ReportChosen -and $script:LastReport -and (Test-Path -LiteralPath $script:LastReport)) { return $true }
    $has = $script:LastReport -and (Test-Path -LiteralPath $script:LastReport)
    $buttons = @(
        $(if ($has) { @{ Tag = 'last'; Label = "Use $(Split-Path -Leaf $script:LastReport)" } })
        @{ Tag = 'pick'; Label = 'Choose a report...' }
        @{ Tag = ''; Label = 'Cancel' }
    ) | Where-Object { $_ }
    $text = 'No analysis is in memory. The AI summary can work on a report already written: its findings are read from it and the summary is added to it, nothing is analyzed or downloaded. The snapshot of that report must still be there (the snapshot chosen above, the snapshot folder or the folder of the report): the names replaced with tokens come from it.'
    switch (Show-Choice -Heading 'Use an existing report?' -Text $text -Buttons $buttons) {
        'last' { return $true }
        'pick' { return [bool](Select-OtherReport | Select-Object -Last 1) }
    }
    return $false
}

function Invoke-Ai {
    param([bool]$Send)
    if (-not $script:Kept -and -not (Select-AiReport)) { return }
    $target = $script:LastReport
    if ($script:Kept) { $ai = @{ AiContinue = $true } }
    else {
        # The report's snapshot is looked for here; nothing else of the form counts: the report is done.
        $sources = @(@($ui.SnapshotBox.Text.Trim(), $script:LastSnapshot, (Get-SnapshotDir), (Split-Path -Parent $target)) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
        $ai = @{ AiReport = $target; Snapshot = $sources }
        if ($ui.SnapPassBox.SecurePassword.Length -gt 0) { $ai['SnapshotPassword'] = $ui.SnapPassBox.SecurePassword.Copy() }
        # The step would ask for the password at a console this window does not have.
        else {
            Show-Results $target
            $names = @(if ($script:Res -and $script:Res.Summary) { @($script:Res.Summary.hosts) | ForEach-Object { "$($_.name)" -replace '[^\w\-]', '_' } })
            $locked = @(foreach ($src in $sources) { Get-PasswordSnapshots $src }) | Where-Object { $leaf = $_.Name; @($names | Where-Object { $leaf -like "*$_*" }).Count -gt 0 }
            if (@($locked).Count) { [void][System.Windows.MessageBox]::Show("The snapshot of this report is encrypted with a password ($(@($locked)[0].Name)): type it under Snapshots already collected first.", 'HostBadger'); return }
        }
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
    Start-GuiTask -Label $(if ($Send) { 'Sending to Gemini' } else { 'Writing the AI prompt (dry run)' }) -Work $script:RunScript -Arguments @((Join-Path $root 'HostBadger.ps1'), $ai) -Done {
        param($t)
        if (@($t.Lines | Where-Object { $_ -like 'No analysis kept*' }).Count) { $script:Kept = $false }
        Set-Busy $false 'Ready'
        Update-Outputs
        Show-Results $script:LastReport
        # The log may be on another tab: why a report could not be used is said here too.
        $why = @($t.Lines | Where-Object { $_ -like 'AI report:*' })
        if ($why.Count) { [void][System.Windows.MessageBox]::Show(($why[0] -replace '^AI report: ', ''), 'HostBadger') }
    }
}

function Invoke-Run {
    # Analyze: this machine is collected, then analyzed; snapshots already collected are analyzed. Nothing
    # changes. Fix: this machine only, collected and analyzed, then its fix script previewed and applied
    # after a warning.
    param([switch]$Fix)
    Save-FormChoices
    if ($Fix -and -not (Test-FixChoice)) {
        [void][System.Windows.MessageBox]::Show('Fix: choose a level, or "No fix of the findings" with Debloat, Disable telemetry or both.', 'HostBadger'); return
    }
    # A file named in Your organization that is not there would stop the analysis halfway.
    $missing = @(foreach ($pair in @(@('Exceptions file', $ui.ExceptionsBox), @('Policy file', $ui.PolicyBox), @('Compare with', $ui.CompareBox))) {
            $v = $pair[1].Text.Trim()
            if ($v -and -not (Test-Path -LiteralPath (Get-FullPath $v) -PathType Leaf)) { "$($pair[0]): $v" }
        })
    if ($missing.Count) { [void][System.Windows.MessageBox]::Show("Not found:`n$($missing -join "`n")`n`nCorrect or empty these fields under Your organization.", 'HostBadger'); return }
    $script:ForFix = [bool]$Fix
    $script:ApplyAfter = [bool]$Fix
    if ($Fix -and -not $script:IsAdmin) {
        $answer = [System.Windows.MessageBox]::Show("Fixing this machine needs administrator rights.`n`nRestart the window as administrator now? (Windows asks to confirm; the form is kept.)", 'HostBadger', 'YesNo', 'Warning')
        if ("$answer" -eq 'Yes') { Invoke-Elevate }
        return
    }
    if (-not $Fix -and $ui.SrcMachine.IsChecked -and -not $script:IsAdmin) {
        # A snapshot collected without administrator rights misses what only an administrator can read
        # (security and audit policy among others): those checks come out "not evaluated".
        $answer = [System.Windows.MessageBox]::Show("HostBadger is not running as administrator.`n`nThe collection of this machine cannot read everything (the security and audit policy among others): the checks that need it are listed as not evaluated, and the score covers less.`n`nYes: restart the window as administrator (Windows asks to confirm; the form is kept).`nNo: collect and analyze anyway, with what a standard user can read.`nCancel: do nothing.", 'HostBadger: not administrator', 'YesNoCancel', 'Warning', 'Yes')
        if ("$answer" -eq 'Yes') { Invoke-Elevate; return }
        if ("$answer" -ne 'No') { return }
    }
    if ($Fix -and (Get-ProfileChoice) -eq 'None') { Invoke-ProfileFix; return }
    if ($Fix -and (Test-RecentCollection)) {
        # This machine was collected here a few minutes ago with the same options: no second collection.
        # The preview reads every setting again, so a value changed since then is not set twice.
        $at = $script:LastSnapshotAt.ToString('HH:mm')
        $ui.SnapshotBox.Text = $script:LastSnapshot
        $b = $script:FixBasis
        if ($b -and $b.Snapshot -eq $script:LastSnapshot -and $b.Signature -eq (Get-ParamsSignature (Get-AnalysisParams -ForFix)) -and (Test-Path -LiteralPath $b.Fixes)) {
            $script:ApplyAfter = $false
            Add-Log "Fix: the analysis of this machine collected at $at is used again (same choices); the preview reads every setting again."
            Invoke-FixPreview -Dir $b.Fixes
            return
        }
        Add-Log "Fix: this machine collected at $at is analyzed again with these choices (not collected again)."
        Invoke-Analyze
        return
    }
    if ($Fix -or $ui.SrcMachine.IsChecked) { Invoke-Collect -ThenAnalyze } else { Invoke-Analyze }
}

function Test-RecentCollection {
    # A collection of this machine made in this window less than FixReuseMinutes ago, with the collection
    # options the form has now.
    if (-not $script:LastSnapshot -or -not $script:LastSnapshotAt) { return $false }
    if (-not (Test-Path -LiteralPath $script:LastSnapshot)) { return $false }
    if ($script:LastSnapshotOpts -ne (Get-CollectOptions)) { return $false }
    return ((Get-Date) - $script:LastSnapshotAt).TotalMinutes -lt $script:FixReuseMinutes
}

function Invoke-Elevate {
    # The same window, as administrator (Windows asks to confirm), in the same folder: -Verb RunAs
    # ignores -WorkingDirectory, so the folder goes as -StartIn (as in the guided menu). The choices of
    # the form are saved first, so the new window opens with them.
    Save-FormChoices
    $exe = (Get-Process -Id $PID).Path
    try {
        Start-Process -FilePath $exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-StartIn', "`"$($PWD.ProviderPath -replace '\\$', '\.')`"")
        $window.Close()
    }
    catch { Add-Log "Not restarted: $($_.Exception.Message)" }
}

function Invoke-FixPreview {
    # This machine, after its analysis: preview the fix script, then ask before applying it.
    param([string]$Dir)
    $dir = if ($Dir) { $Dir } else { ($script:LastReport -replace '\.html?$', '') + '_fixes' }
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
        # The question sits in the Fix tab, not in a dialog, so the preview in the log can be read first.
        $ui.ApplyHead.Text = "Apply $($would.Count) change(s) to THIS machine?"
        $ui.ApplyText.Text = "Each one is a WOULD line in the log$(if ($noUndo.Count) { "; $($noUndo.Count) of them are NOT REVERSIBLE (removed apps come back only from the Microsoft Store)" }). A System Restore point is made first (Windows PowerShell 5.1 on a Windows client) and every previous value is saved in a rollback file. Some changes take effect after a restart."
        $ui.ApplyYesBtn.Content = "Apply $($would.Count) change(s)"
        Show-ApplyPanel $true
        Add-Log 'Fix: read the preview, then Apply or Don''t apply (in the Fix tab).'
    }
}
function Show-ApplyPanel {
    # The apply question of the last preview: any other step started meanwhile withdraws it.
    param([bool]$On)
    $script:ApplyPending = $On
    $ui.ApplyPanel.Visibility = if ($On) { 'Visible' } else { 'Collapsed' }
    Update-Actions
}
function Invoke-ProfileFix {
    # No fix of the findings: debloat and telemetry depend only on the role of this machine, so the
    # script is written at once, without collecting or analyzing it. The preview still reads every
    # setting before it would change it.
    $out = (Get-AnalysisParams -ForFix)['OutHtml']
    $dir = ($out -replace '\.html?$', '') + '_fixes'
    $opt = @{ Debloat = [bool]$ui.DebloatChk.IsChecked; Privacy = [bool]$ui.PrivacyChk.IsChecked }
    $script:ProfileFixDir = $dir
    Add-Log 'Fix: no fix of the findings, so this machine is not collected or analyzed: the script holds the chosen debloat and telemetry settings for its role.'
    Start-GuiTask -Label 'Writing the fix script' -Work $script:ProfileFixWork -Arguments @($root, $dir, $opt) -Done {
        param($t)
        Set-Busy $false 'Ready'
        if (@($t.Results | Where-Object { $_.Kind -eq 'profilefix' }).Count -eq 0) { Add-Log 'Fix: the script was not written (see the log).'; return }
        Invoke-FixPreview -Dir $script:ProfileFixDir
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
    if ($ui.PipesChk.IsChecked) { $p['NamedPipes'] = $true }
    if ($ui.EncPass.IsChecked) {
        $pw = Get-PlainSecret $ui.EncPassBox
        if (-not $pw) { [void][System.Windows.MessageBox]::Show('Type the password for the snapshot.', 'HostBadger'); return }
        $p['EncryptPassword'] = $pw
    }
    elseif ($ui.EncCert.IsChecked) {
        if (-not $ui.EncCertBox.Text.Trim()) { [void][System.Windows.MessageBox]::Show('Give the .cer path or the thumbprint of the certificate.', 'HostBadger'); return }
        $p['EncryptCertificate'] = $ui.EncCertBox.Text.Trim()
    }
    $script:PendingCollectOpts = Get-CollectOptions
    Start-GuiTask -Label 'Collecting this machine (read only)' -Work $script:RunScript -Arguments @((Join-Path $root 'Collect-HostSnapshot.ps1'), $p) -Done {
        param($t)
        $snap = @($t.Lines | Where-Object { $_ -like 'Snapshot: *' } | ForEach-Object { $_.Substring(10).Trim() }) | Select-Object -Last 1
        if ($snap) {
            $script:LastSnapshot = $snap
            $script:LastSnapshotAt = Get-Date
            $script:LastSnapshotOpts = $script:PendingCollectOpts
            $script:FixBasis = $null
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
$ui.DebloatChk.Add_Click({ Update-RemPanel })
$ui.PrivacyChk.Add_Click({ Update-RemPanel })
$ui.ReportBox.Add_LostFocus({ Update-CatalogChoices; Update-RemPanel })
$ui.SrcMachine.Add_Checked({ Update-Source })
$ui.SrcSnap.Add_Checked({ Update-Source })
$ui.SnapshotBox.Add_TextChanged({ Update-Source })
# Typing a password or a certificate means that encryption: without it the box would be ignored.
$ui.EncPassBox.Add_GotFocus({ $ui.EncPass.IsChecked = $true })
$ui.EncCertBox.Add_GotFocus({ $ui.EncCert.IsChecked = $true })
function Select-FormFile {
    # File... of a path field: opens where the field points (else the report folder) and fills it.
    param($Box, [string]$Filter)
    $d = New-Object Microsoft.Win32.OpenFileDialog; $d.Filter = $Filter
    $cur = $Box.Text.Trim()
    $start = if ($cur) { Split-Path -Parent (Get-FullPath $cur) } else { Get-ReportDir }
    if ($start -and (Test-Path -LiteralPath $start -PathType Container)) { $d.InitialDirectory = $start }
    if ($d.ShowDialog()) { $Box.Text = $d.FileName }
}
$ui.ExceptionsFileBtn.Add_Click({ Select-FormFile $ui.ExceptionsBox 'Exceptions (JSON)|*.json|All files|*.*' })
$ui.PolicyFileBtn.Add_Click({ Select-FormFile $ui.PolicyBox 'Organization policy (JSON)|*.json|All files|*.*' })
$ui.CompareFileBtn.Add_Click({ Select-FormFile $ui.CompareBox 'Findings of an earlier report (CSV)|*.csv|All files|*.*' })
$ui.EncCertBtn.Add_Click({ $d = New-Object Microsoft.Win32.OpenFileDialog; $d.Filter = 'Certificates|*.cer;*.crt;*.pem|All files|*.*'; if ($d.ShowDialog()) { $ui.EncCertBox.Text = $d.FileName; $ui.EncCert.IsChecked = $true } })
$ui.RunBtn.Add_Click({ Invoke-Run })
$ui.FixBtn.Add_Click({ Invoke-Run -Fix })
$ui.StopBtn.Add_Click({ Stop-GuiTask })
$ui.FixStopBtn.Add_Click({ Stop-GuiTask })
$ui.ApplyYesBtn.Add_Click({ Show-ApplyPanel $false; Invoke-FixApply })
$ui.ApplyNoBtn.Add_Click({ Show-ApplyPanel $false; Add-Log 'Fix: not applied, nothing changed.' })
$ui.SafetyBtn.Add_Click({ Start-GuiTask -Label 'Safety review' -Work $script:RunScript -Arguments @((Join-Path $root 'Test-HostBadgerSafety.ps1'), @{}) -Done { } })
$ui.OpenBtn.Add_Click({ if ($script:LastReport -and (Test-Path -LiteralPath $script:LastReport)) { Invoke-Item -LiteralPath $script:LastReport } })

$ui.SettingsBtn.Add_Click({ Show-Settings })
$ui.AiPickBtn.Add_Click({ [void](Select-OtherReport) })
$ui.ResPickBtn.Add_Click({ [void](Select-OtherReport) })
$ui.ResOpenBtn.Add_Click({ if ($script:Res -and $script:Res.Path -and (Test-Path -LiteralPath $script:Res.Path)) { try { Invoke-Item -LiteralPath $script:Res.Path } catch { Add-Log "Not opened: $($_.Exception.Message)" } } })
# The Results tab reads the report when it is first shown (SelectionChanged also bubbles up from the
# lists and the table inside the tabs).
$ui.Tabs.Add_SelectionChanged({ param($s, $e) if ($e.OriginalSource -eq $ui.Tabs -and $ui.Tabs.SelectedItem -eq $ui.TabResults) { Show-Results $script:LastReport } })
$ui.ResHost.Add_SelectionChanged({ Update-ResultsView })
$ui.ResCats.Add_SelectionChanged({ Update-ResultsView })
$ui.ResCisChk.Add_Click({ Update-ResultsView })
$ui.ResStigChk.Add_Click({ Update-ResultsView })
$ui.ResGrid.Add_SelectionChanged({ Show-ResultDetail $ui.ResGrid.SelectedItem })
# The search runs when typing pauses, not at every key.
$script:SearchTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:SearchTimer.Interval = [TimeSpan]::FromMilliseconds(250)
$script:SearchTimer.Add_Tick({ $script:SearchTimer.Stop(); Update-ResultsView })
$ui.ResSearch.Add_TextChanged({ if (-not $script:ResBusy) { $script:SearchTimer.Stop(); $script:SearchTimer.Start() } })
$window.Add_PreviewKeyDown({
        param($s, $e)
        if ($e.Key -eq 'F' -and [System.Windows.Input.Keyboard]::Modifiers -eq 'Control') {
            $ui.Tabs.SelectedItem = $ui.TabResults; [void]$ui.ResSearch.Focus(); $ui.ResSearch.SelectAll(); $e.Handled = $true
        }
    })
$ui.SnapshotBox.Add_TextChanged({ Update-AiTarget })
$ui.AiDryBtn.Add_Click({ Invoke-Ai $false })
$ui.AiSendBtn.Add_Click({ Invoke-Ai $true })
$ui.UpdateCheckBtn.Add_Click({ Invoke-UpdateCheck })
$ui.UpdateBtn.Add_Click({ Invoke-Update })
$ui.ElevateBtn.Add_Click({ Invoke-Elevate })
$window.Add_Activated({ if (-not $script:Task -and $ui.SnapshotNote.Text -like 'The newest snapshot*') { Select-LatestSnapshot (Get-SnapshotDir) } })
$window.Add_Closing({
        param($s, $e)
        if ($script:Task) {
            # Closing stops the step halfway: a fix script stopped while applying leaves part of the changes.
            $warn = if ($script:Task.Label -like 'Applying*') { "The fixes are being applied: closing now stops them halfway (the rollback file holds only what was already changed).`n`nClose anyway?" } else { "$($script:Task.Label) is still running: closing stops it.`n`nClose anyway?" }
            if ("$([System.Windows.MessageBox]::Show($warn, 'HostBadger', 'YesNo', 'Warning', 'No'))" -ne 'Yes') { $e.Cancel = $true; return }
        }
        $script:Timer.Stop(); $script:SearchTimer.Stop()
        if ($script:Task) { try { $script:Task.Ps.Stop() } catch { } }
    })

# A small screen (a 1366x768 laptop) gets a window that fits its work area.
$wa = [System.Windows.SystemParameters]::WorkArea
foreach ($dim in @(@('Width', 'MinWidth', $wa.Width), @('Height', 'MinHeight', $wa.Height))) {
    if ($dim[2] -gt 0) { $window.($dim[1]) = [Math]::Min($window.($dim[1]), $dim[2]); $window.($dim[0]) = [Math]::Min($window.($dim[0]), $dim[2]) }
}

Initialize-Form
Add-Log "HostBadger v$($script:LocalVersion). Choose what to analyze (this machine, or snapshots already collected) and press the yellow button."
if ($NoShow) {
    $sw = New-SettingsWindow
    "Auto update check: setting $(Test-AutoUpdateCheck), box $($sw.Ui.SetAutoUpdate.IsChecked)"
    "GUI ready: $($ui.Count) controls, $($script:CatalogBoxes.Count) catalogs, version $($script:LocalVersion); settings: $($sw.Ui.Count) controls, $($sw.Boxes.Count) catalogs, $($ui.ProfilePanel.Children.Count) fix levels"
    # Fix this machine needs something to change: a level, or no level with Debloat or telemetry.
    $rbs = @($ui.ProfilePanel.Children)
    $ui.DebloatChk.IsChecked = $false; $ui.PrivacyChk.IsChecked = $false
    ($rbs | Where-Object { "$($_.Tag)" -eq 'None' }).IsChecked = $true; Update-RemPanel; $fixNone = $ui.FixBtn.IsEnabled
    $ui.DebloatChk.IsChecked = $true; Update-RemPanel; $fixDebloat = $ui.FixBtn.IsEnabled
    ($rbs | Where-Object { "$($_.Tag)" -eq 'Essential' }).IsChecked = $true; Update-RemPanel; $fixLevel = $ui.FixBtn.IsEnabled
    foreach ($rb in $rbs) { $rb.IsChecked = $false }; Update-RemPanel; $fixNothing = $ui.FixBtn.IsEnabled
    "Fix button: nothing chosen $fixNothing, no level $fixNone, no level with debloat $fixDebloat, a level $fixLevel"
    # The fixes have their own tab, with the log of Analyze repeated there.
    $fixTab = $ui.FixBtn; while ($fixTab -and $fixTab -isnot [System.Windows.Controls.TabItem]) { $fixTab = [System.Windows.LogicalTreeHelper]::GetParent($fixTab) }
    "Fix tab: button in $($fixTab.Header), options in $(if ([System.Windows.LogicalTreeHelper]::GetParent($ui.RemPanel)) { $p = $ui.RemPanel; while ($p -and $p -isnot [System.Windows.Controls.TabItem]) { $p = [System.Windows.LogicalTreeHelper]::GetParent($p) }; $p.Header }), scripts option in $($p = $ui.RemChk; while ($p -and $p -isnot [System.Windows.Controls.TabItem]) { $p = [System.Windows.LogicalTreeHelper]::GetParent($p) }; $p.Header), log repeated $($ui.FixLogBox.Text.Length -gt 0 -and $ui.FixLogBox.Text -eq $ui.LogBox.Text)"
    # Fix this machine reuses a recent collection with the same options, and its analysis while the
    # choices are the same (the paths of the files do not count).
    $script:LastSnapshot = $PSCommandPath; $script:LastSnapshotOpts = Get-CollectOptions
    $script:LastSnapshotAt = (Get-Date).AddMinutes(-5); $recent = Test-RecentCollection
    $script:LastSnapshotAt = (Get-Date).AddMinutes(-$script:FixReuseMinutes - 1); $old = Test-RecentCollection
    $script:LastSnapshotAt = (Get-Date).AddMinutes(-5); $ui.SkipAclChk.IsChecked = -not $ui.SkipAclChk.IsChecked; $otherOpts = Test-RecentCollection; $ui.SkipAclChk.IsChecked = -not $ui.SkipAclChk.IsChecked
    $sig = Get-ParamsSignature (Get-AnalysisParams -ForFix)
    $ap2 = Get-AnalysisParams -ForFix; $ap2['OutHtml'] = 'C:\elsewhere\r.html'; $ap2['OutRemediation'] = 'C:\elsewhere\r_fixes'; $samePaths = (Get-ParamsSignature $ap2) -eq $sig
    $ap2['AllowedAdmins'] = @('someone'); $otherChoice = (Get-ParamsSignature $ap2) -eq $sig
    $script:LastSnapshot = ''; $script:LastSnapshotAt = $null
    "Fix reuse: recent $recent, older $old, other options $otherOpts, same choices elsewhere $samePaths, other choices $otherChoice"
    # The apply question is a panel of the Fix tab (the log stays readable), withdrawn by any other step.
    Show-ApplyPanel $true; $askOn = "$($ui.ApplyPanel.Visibility) $($ui.ApplyYesBtn.IsEnabled)"
    Show-ApplyPanel $false; $askOff = "$($ui.ApplyPanel.Visibility) $($ui.ApplyYesBtn.IsEnabled)"
    "Apply question: shown $askOn, withdrawn $askOff"
    # The AI questions: their buttons, on this window's look, and no send without the key.
    $savedKey = $env:GEMINI_API_KEY; $env:GEMINI_API_KEY = ''
    $off = New-ChoiceWindow -Heading 'h' -Text 't' -Buttons (Get-AiOfferButtons)
    $env:GEMINI_API_KEY = 'x'
    $on = New-ChoiceWindow -Heading 'h' -Text 't' -Buttons (Get-AiOfferButtons)
    $env:GEMINI_API_KEY = $savedKey
    "AI offer: $(@($on.Ui.ChoiceButtons.Children | ForEach-Object { $_.Content }) -join ' / '); send with a key $(@($on.Ui.ChoiceButtons.Children)[0].IsEnabled), without $(@($off.Ui.ChoiceButtons.Children)[0].IsEnabled)"
    $on.Window.Close(); $off.Window.Close()
    # The Results tab on the demo report: every finding read, the categories listed, a finding detailed.
    Show-Results (Join-Path $root 'examples\demo_report.html')
    $ui.ResCisChk.IsChecked = $true; $ui.ResStigChk.IsChecked = $true; Update-ResultsView
    $described = @($script:Res.Rows | Where-Object { (Get-CheckInfo)[$_.Type].Description } | ForEach-Object { $_.Type } | Sort-Object -Unique).Count
    $types = @($script:Res.Rows | ForEach-Object { $_.Type } | Sort-Object -Unique).Count
    "Results: $($script:Res.Rows.Count) findings, $($script:Res.Hosts.Count) hosts, $($ui.ResCats.Items.Count - 2) categories, $($ui.ResGrid.Items.Count) shown, $described of $types checks described, $($ui.ResDetail.Children.Count) detail lines"
    # The overview it opens on: the scores of the hosts, and the details of one when it is chosen.
    $ovAll = $ui.ResOverview.Children.Count; $lowest = $ui.ScoreNum.Text
    $ui.ResHost.SelectedIndex = 1
    "Overview: $(@(Get-SummaryHosts).Count) hosts scored, badge $lowest for all hosts and $($ui.ScoreNum.Text) for $($ui.ResHost.SelectedItem.Tag); $ovAll elements for all hosts, $($ui.ResOverview.Children.Count) for one ($($ui.ResCats.SelectedItem.Tag))"
    $sw.Window.Close()
    $script:Rs.Dispose()
    return
}
# The last report is read once the window is drawn, so the Results tab shows its count from the start.
# The update check of Settings runs then too: never with -NoShow, which returned above.
$window.Add_ContentRendered({ Show-Results $script:LastReport; if (Test-AutoUpdateCheck) { Invoke-UpdateCheck } })
[void]$window.ShowDialog()
$script:Rs.Dispose()
