package br.org.generation.farmacia.repository;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.org.generation.farmacia.model.Produto;

@Repository
public interface ProdutoRepository extends JpaRepository<Produto, Long>{
	
	public List<Produto> findAllByDescricaoProdContainingIgnoreCase(String descricaoProd);
	
	public List <Produto> findByPrecoProdGreaterThanOrderByPrecoProd(BigDecimal precoProd);
	
	public List <Produto> findByPrecoProdLessThanOrderByPrecoProdDesc(BigDecimal precoProd);
	
	public List <Produto> findByNomeProdAndLaboratorioProd(String nomeProd, String laboratorioProd);
	
	public List <Produto> findByNomeProdOrLaboratorioProd(String nomeProd, String laboratorioProd);

}
