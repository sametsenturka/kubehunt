package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/sametsenturka/kubehunt/internal/app"
	"github.com/sametsenturka/kubehunt/internal/report/terminal"
	"github.com/sametsenturka/kubehunt/internal/version"
)

func NewRootCommand() *cobra.Command {
	return newRootCommand(app.NewScanner(), os.Stdout)
}

func newRootCommand(scanner app.ClusterScanner, output io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "kubehunt",
		Short:         "Kubernetes security posture scanner",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(output)
	root.AddCommand(newScanCommand(scanner, output))
	root.AddCommand(newVersionCommand(output))
	return root
}

func newScanCommand(scanner app.ClusterScanner, output io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "scan",
		Short: "Collect Kubernetes cluster state",
	}
	command.AddCommand(newScanClusterCommand(scanner, output))
	return command
}

func newScanClusterCommand(scanner app.ClusterScanner, output io.Writer) *cobra.Command {
	var options app.ScanOptions
	command := &cobra.Command{
		Use:   "cluster",
		Short: "Collect and summarize the selected Kubernetes cluster",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if scanner == nil {
				return fmt.Errorf("scan cluster: scanner is not configured")
			}
			state, err := scanner.Scan(command.Context(), options)
			if err != nil {
				return err
			}
			if err := (terminal.InventoryReporter{}).Render(output, state); err != nil {
				return fmt.Errorf("scan cluster: %w", err)
			}
			return nil
		},
	}
	command.Flags().StringVar(&options.Kubeconfig, "kubeconfig", "", "path to the kubeconfig file")
	command.Flags().StringVar(&options.Context, "context", "", "kubeconfig context to use (defaults to the current context)")
	command.Flags().StringSliceVarP(&options.Namespaces, "namespace", "n", nil, "namespace to scan (repeat or comma-separate for multiple namespaces)")
	command.Flags().BoolVar(&options.AllowExecCredential, "allow-exec-credential", false, "allow trusted kubeconfig exec or auth-provider credentials")
	return command
}

func newVersionCommand(output io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if _, err := fmt.Fprintln(output, version.String()); err != nil {
				return fmt.Errorf("print version: %w", err)
			}
			return nil
		},
	}
}
