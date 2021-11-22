package br.org.generation.farmacia.controller;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.org.generation.farmacia.model.Produto;
import br.org.generation.farmacia.repository.ProdutoRepository;

@RestController
@RequestMapping("/produto")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class ProdutoController {

	@Autowired
	private ProdutoRepository produtoRepository;

	@GetMapping
	public ResponseEntity<List<Produto>> getAllProd() {
		return ResponseEntity.ok(produtoRepository.findAll());
	}

	@GetMapping("/{id}")
	public ResponseEntity<Produto> getByIdProd(@PathVariable long id) {
		return produtoRepository.findById(id).map(resp -> ResponseEntity.ok(resp))
				.orElse(ResponseEntity.notFound().build());
	}

	@GetMapping("/descricao/{descricao}")
	public ResponseEntity<List<Produto>> getByDescricaoProd(@PathVariable String descricao) {
		return ResponseEntity.ok(produtoRepository.findAllByDescricaoProdContainingIgnoreCase(descricao));
	}

	@PostMapping
	public ResponseEntity<Produto> postProd(@RequestBody Produto produto) {
		return ResponseEntity.status(HttpStatus.CREATED).body(produtoRepository.save(produto));
	}

	@PutMapping
	public ResponseEntity<Produto> putProd(@RequestBody Produto produto) {
		return ResponseEntity.status(HttpStatus.OK).body(produtoRepository.save(produto));
	}

	@DeleteMapping("/{id}")
	public void deleteCateg(@PathVariable long id) {
		produtoRepository.deleteById(id);
	}

	// Consulta pelo preço maior do que o preço digitado emm ordem crescente
	@GetMapping("/preco_maior/{preco}")
	public ResponseEntity<List<Produto>> getPrecoMaiorQue(@PathVariable BigDecimal preco) {
		return ResponseEntity.ok(produtoRepository.findByPrecoProdGreaterThanOrderByPrecoProd(preco));
	}

	// Consulta pelo preço menor do que o preço digitado em ordem decrescente
	@GetMapping("/preco_menor/{preco}")
	public ResponseEntity<List<Produto>> getPrecoMenorQue(@PathVariable BigDecimal preco) {
		return ResponseEntity.ok(produtoRepository.findByPrecoProdLessThanOrderByPrecoProdDesc(preco));
	}

	// Consulta por nome ou laboratório
	@GetMapping("/nome/{nome}/oulaboratorio/{laboratorio}")
	public ResponseEntity<List<Produto>> getByNomeOuLaboratorio(@PathVariable String nome,
			@PathVariable String laboratorio) {
		return ResponseEntity.ok(produtoRepository.findByNomeProdOrLaboratorioProd(nome, laboratorio));
	}

	// Consulta por nome e laboratório
	@GetMapping("/nome/{nome}/elaboratorio/{laboratorio}")
	public ResponseEntity<List<Produto>> getByNomeELaboratorio(@PathVariable String nome,
			@PathVariable String laboratorio) {
		return ResponseEntity.ok(produtoRepository.findByNomeProdAndLaboratorioProd(nome, laboratorio));
	}

}
