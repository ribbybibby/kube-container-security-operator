GOPKG = github.com/ribbybibby/kube-container-security-operator

.PHONY: vendor
vendor:
	go mod vendor

.PHONY: deepcopy
deepcopy:
	deepcopy-gen \
	-i github.com/ribbybibby/kube-container-security-operator/apis/secscan/v1alpha1 \
	-v=4 \
	--logtostderr \
	--output-file-base zz_generated.deepcopy
	go fmt apis/secscan/v1alpha1/zz_generated.deepcopy.go

.PHONY: openapi
openapi:
	openapi-gen \
	-i github.com/ribbybibby/kube-container-security-operator/apis/secscan/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/api/core/v1 \
	-v=4 \
	-p github.com/ribbybibby/kube-container-security-operator/apis/secscan/v1alpha1
	go fmt apis/secscan/v1alpha1/openapi_generated.go

.PHONY: clientset
clientset:
	client-gen \
	-v=4 \
	--input-base     "" \
	--clientset-name "versioned" \
	--input	         "$(GOPKG)/apis/secscan/v1alpha1" \
	--output-package "$(GOPKG)/generated"

.PHONY: listers
listers:
	lister-gen \
	-v=4 \
	--input-dirs     "$(GOPKG)/apis/secscan/v1alpha1" \
	--output-package "$(GOPKG)/generated/listers"

.PHONY: informers
informers:
	informer-gen \
	-v=4 \
	--versioned-clientset-package "$(GOPKG)/generated/versioned" \
	--listers-package "$(GOPKG)/generated/listers" \
	--input-dirs      "$(GOPKG)/apis/secscan/v1alpha1" \
	--output-package  "$(GOPKG)/generated/informers"
.PHONY: crd
crd:
	controller-gen crd:trivialVersions=true paths="./..." output:crd:artifacts:config=deploy

.PHONY: codegen
codegen: deepcopy clientset crd
