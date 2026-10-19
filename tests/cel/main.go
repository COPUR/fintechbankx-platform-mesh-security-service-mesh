// Evaluates a ValidatingAdmissionPolicy's CEL (spec.variables and
// spec.validations) with cel-go against admission cases, the way the
// kube-apiserver composes them: variables in declaration order under
// `variables`, then every validation; a request is admitted only if every
// validation evaluates to true. A compile or evaluation error counts as a
// rejection (failurePolicy Fail).
//
// Input (stdin, JSON): {"policy": <spec>, "cases": [{"name", "request",
// "object", "namespaceObject"}]}. Output (stdout, JSON): one result per case.
//
// Not modelled: OpenAPI-typed checking (everything is dyn), CEL cost limits,
// and the Kubernetes CEL libraries beyond ext.Strings (the policy uses none).
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

type expr struct {
	Name              string `json:"name"`
	Expression        string `json:"expression"`
	Message           string `json:"message"`
	MessageExpression string `json:"messageExpression"`
}

type input struct {
	Policy struct {
		Variables   []expr `json:"variables"`
		Validations []expr `json:"validations"`
	} `json:"policy"`
	Cases []struct {
		Name            string         `json:"name"`
		Request         map[string]any `json:"request"`
		Object          map[string]any `json:"object"`
		NamespaceObject map[string]any `json:"namespaceObject"`
	} `json:"cases"`
}

type result struct {
	Name     string   `json:"name"`
	Allowed  bool     `json:"allowed"`
	Messages []string `json:"messages"`
}

func main() {
	var in input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fail(err)
	}
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("request", cel.DynType),
		cel.Variable("namespaceObject", cel.DynType),
		cel.Variable("params", cel.DynType),
		cel.Variable("variables", cel.MapType(cel.StringType, cel.DynType)),
		ext.Strings(),
	)
	if err != nil {
		fail(err)
	}
	compile := func(src string) cel.Program {
		ast, iss := env.Compile(src)
		if iss.Err() != nil {
			fail(fmt.Errorf("compile %q: %w", src, iss.Err()))
		}
		prg, err := env.Program(ast)
		if err != nil {
			fail(err)
		}
		return prg
	}
	vars := make([]cel.Program, len(in.Policy.Variables))
	for i, v := range in.Policy.Variables {
		vars[i] = compile(v.Expression)
	}
	checks := make([]cel.Program, len(in.Policy.Validations))
	msgs := make([]cel.Program, len(in.Policy.Validations))
	for i, v := range in.Policy.Validations {
		checks[i] = compile(v.Expression)
		if v.MessageExpression != "" {
			msgs[i] = compile(v.MessageExpression)
		}
	}

	out := []result{}
	for _, c := range in.Cases {
		variables := map[string]any{}
		activation := map[string]any{
			"object": c.Object, "oldObject": nil, "request": c.Request,
			"namespaceObject": c.NamespaceObject, "params": nil, "variables": variables,
		}
		r := result{Name: c.Name, Allowed: true, Messages: []string{}}
		for i, v := range in.Policy.Variables {
			val, _, err := vars[i].Eval(activation)
			if err != nil {
				r.Allowed = false
				r.Messages = append(r.Messages, fmt.Sprintf("variable %s: %v", v.Name, err))
				continue
			}
			variables[v.Name] = val
		}
		for i, v := range in.Policy.Validations {
			val, _, err := checks[i].Eval(activation)
			if err == nil && val.Value() == true {
				continue
			}
			r.Allowed = false
			switch {
			case err != nil:
				r.Messages = append(r.Messages, fmt.Sprintf("validation %d error: %v", i, err))
			case msgs[i] != nil:
				m, _, merr := msgs[i].Eval(activation)
				if merr != nil {
					r.Messages = append(r.Messages, v.Message)
				} else {
					r.Messages = append(r.Messages, fmt.Sprint(m.Value()))
				}
			default:
				r.Messages = append(r.Messages, v.Message)
			}
		}
		out = append(out, r)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
