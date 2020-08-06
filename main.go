package main

import (
	"flag"
	"github.com/ribbybibby/kube-container-security-operator/adapter/trivy"
	secscanv1alpha1 "github.com/ribbybibby/kube-container-security-operator/apis/secscan/v1alpha1"
	"github.com/ribbybibby/kube-container-security-operator/controllers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"strings"
	"time"
)

type namespaceFlags []string

func (nf *namespaceFlags) String() string {
	return strings.Join(*nf, ",")
}

func (nf *namespaceFlags) Set(value string) error {
	*nf = append(*nf, value)
	return nil
}

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")

	trivyClient     = flag.Bool("trivy-client", true, "Run trivy in client mode")
	resyncPeriod    = flag.Duration("resync-period", 10*time.Minute, "Resync period")
	rescanThreshold = flag.Duration("rescan-theshold", 60*time.Minute, "The amount of time before scanning an image again")
	metricsAddr     = flag.String("metrics-address", ":8080", "The address to serve metrics on")
	workers         = flag.Int("workers", 1, "Workers")
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = secscanv1alpha1.AddToScheme(scheme)
}

func main() {
	var namespaces namespaceFlags
	flag.Var(&namespaces, "namespaces", "Restrict operation to specific namespaces")

	logOpts := zap.Options{}
	logOpts.BindFlags(flag.CommandLine)

	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&logOpts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		NewCache:           cache.MultiNamespacedCacheBuilder(namespaces),
		MetricsBindAddress: *metricsAddr,
		LeaderElection:     false,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Setup the pod scanner
	if err = (&controllers.PodScanner{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("podscanner"),
		Options: controller.Options{
			MaxConcurrentReconciles: *workers,
		},
		RescanThreshold: *rescanThreshold,
		Adapter:         &trivy.Client{},
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "name", "podscanner")
		os.Exit(1)
	}

	// Setup the vulnberabilityreport reconciler
	if err = (&controllers.VulnerabilityReportReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("vulnerabilityreportreconciler"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "name", "vulnerabilityreportreconciler")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
