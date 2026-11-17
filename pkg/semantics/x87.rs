//! Shared helpers for one coupled x87 operation. The closed schema lives in the
//! runtime so standalone users do not need a separate module to use Expr::x87.
//! This module captures immutable incoming operands/environment and exposes
//! status/tag/commit before any possibly unavailable result is selected.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X87Outputs {
    expression: X87Expression,
    pub status: Expr,
    pub tags: Expr,
    pub commit: Expr,
}
impl X87Outputs {
    /// Project a statically admitted output. Dynamic availability remains the
    /// engine's contract: use value_when/value_or for outputs gated by commit.
    pub fn project(&self, projection: X87Projection) -> Result<Expr, EvalError> {
        Expr::x87(X87Expression {
            projection,
            ..self.expression.clone()
        })
    }
    /// Select data only on commit and the caller's additional availability
    /// condition (for example, C2 clear before a transcendental pushes ST1).
    /// Status/tags update even without commit and must use their bound fields.
    pub fn value_when(
        &self,
        projection: X87Projection,
        condition: Expr,
        otherwise: Expr,
    ) -> Result<Expr, EvalError> {
        if !matches!(
            projection,
            X87Projection::Result { .. }
                | X87Projection::Store { .. }
                | X87Projection::CompareFlag(_)
        ) || condition.ty.width != 1
        {
            return Err(EvalError::InvalidExpression);
        }
        let value = self.project(projection)?;
        if value.ty.width != otherwise.ty.width {
            return Err(EvalError::InvalidExpression);
        }
        Ok(Expr::select(
            Expr::binary(BinaryOp::And, self.commit.clone(), condition),
            value,
            otherwise,
        ))
    }
    pub fn value_or(&self, projection: X87Projection, otherwise: Expr) -> Result<Expr, EvalError> {
        self.value_when(projection, Expr::constant(1, 1), otherwise)
    }
}
/// Capture one operation without architectural effects. The caller owns x87
/// waiting/exception guards and memory-access predication. Inputs must already
/// describe the correct logical operands; no physical stack bank is invented.
/// Malformed operand dimensions reject before mutating the recipe. The complete
/// recipe graph is checked by Recipe::validate after its bindings are assembled.
pub fn capture(
    recipe: &mut Recipe,
    mut expression: X87Expression,
) -> Result<X87Outputs, EvalError> {
    expression.validate_dimensions()?;
    for input in &mut expression.inputs {
        for chunk in &mut input.chunks {
            *chunk = recipe.bind(chunk.clone());
        }
    }
    expression.control = Box::new(recipe.bind(*expression.control));
    expression.status = Box::new(recipe.bind(*expression.status));
    expression.tags = Box::new(recipe.bind(*expression.tags));
    let project = |projection| {
        Expr::x87(X87Expression {
            projection,
            ..expression.clone()
        })
    };
    let status = recipe.bind(project(X87Projection::Status)?);
    let tags = recipe.bind(project(X87Projection::Tags)?);
    let commit = recipe.bind(project(X87Projection::Commit)?);
    Ok(X87Outputs {
        expression,
        status,
        tags,
        commit,
    })
}
